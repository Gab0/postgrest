{-|
Module      : PostgREST.Query.Statements
Description : PostgREST single SQL statements.

This module constructs single SQL statements that can be parametrized and prepared.

- It consumes the SqlQuery types generated by the QueryBuilder module.
- It generates the body format and some headers of the final HTTP response.
-}
module PostgREST.Query.Statements
  ( prepareWrite
  , prepareRead
  , prepareCall
  , preparePlanRows
  , ResultSet (..)
  ) where

import qualified Data.Aeson.Lens                   as L
import qualified Data.ByteString.Char8             as BS
import qualified Hasql.Decoders                    as HD
import qualified Hasql.DynamicStatements.Snippet   as SQL
import qualified Hasql.DynamicStatements.Statement as SQL
import qualified Hasql.Statement                   as SQL

import Control.Lens ((^?))

import PostgREST.ApiRequest.Preferences
import PostgREST.MediaType               (MTVndPlanFormat (..),
                                          MediaType (..))
import PostgREST.Query.SqlFragment
import PostgREST.SchemaCache.Identifiers (QualifiedIdentifier)
import PostgREST.SchemaCache.Routine     (MediaHandler (..), Routine,
                                          funcReturnsSingle)

import Protolude

-- | Standard result set format used for all queries
data ResultSet
  = RSStandard
  { rsTableTotal :: Maybe Int64
  -- ^ count of all the table rows
  , rsQueryTotal :: Int64
  -- ^ count of the query rows
  , rsLocation   :: [(BS.ByteString, BS.ByteString)]
  -- ^ The Location header(only used for inserts) is represented as a list of strings containing
  -- variable bindings like @"k1=eq.42"@, or the empty list if there is no location header.
  , rsBody       :: BS.ByteString
  -- ^ the aggregated body of the query
  , rsGucHeaders :: Maybe BS.ByteString
  -- ^ the HTTP headers to be added to the response
  , rsGucStatus  :: Maybe Text
  -- ^ the HTTP status to be added to the response
  , rsInserted   :: Maybe Int64
  -- ^ the number of rows inserted (Only used for upserts)
  }
  | RSPlan BS.ByteString -- ^ the plan of the query


prepareWrite :: QualifiedIdentifier -> SQL.Snippet -> SQL.Snippet -> Bool -> Bool -> MediaType -> MediaHandler ->
                Maybe PreferRepresentation -> Maybe PreferResolution -> [Text] -> Bool -> SQL.Statement () ResultSet
prepareWrite qi selectQuery mutateQuery isInsert isPut mt handler rep resolution pKeys =
  SQL.dynamicallyParameterized (mtSnippet mt snippet) decodeIt
 where
  checkUpsert snip = if isInsert && (isPut || resolution == Just MergeDuplicates) then snip else "''"
  pgrstInsertedF = checkUpsert "nullif(current_setting('pgrst.inserted', true),'')::int"
  snippet =
    "WITH " <> sourceCTE <> " AS (" <> mutateQuery <> ") " <>
    "SELECT " <>
      "'' AS total_result_set, " <>
      "pg_catalog.count(_postgrest_t) AS page_total, " <>
      locF <> " AS header, " <>
      handlerF Nothing qi handler <> " AS body, " <>
      responseHeadersF <> " AS response_headers, " <>
      responseStatusF  <> " AS response_status, " <>
      pgrstInsertedF <> " AS response_inserted " <>
    "FROM (" <> selectF <> ") _postgrest_t"

  locF =
    if isInsert && rep == Just HeadersOnly
      then
        "CASE WHEN pg_catalog.count(_postgrest_t) = 1 " <>
          "THEN coalesce(" <> locationF pKeys <> ", " <> noLocationF <> ") " <>
          "ELSE " <> noLocationF <> " " <>
        "END"
      else noLocationF

  selectF
    -- prevent using any of the column names in ?select= when no response is returned from the CTE
    | handler == NoAgg = "SELECT * FROM " <> sourceCTE
    | otherwise        = selectQuery

  decodeIt :: HD.Result ResultSet
  decodeIt = case mt of
    MTVndPlan{} -> planRow
    _           -> fromMaybe (RSStandard Nothing 0 mempty mempty Nothing Nothing Nothing) <$> HD.rowMaybe (standardRow False)

prepareRead :: QualifiedIdentifier -> SQL.Snippet -> SQL.Snippet -> Bool -> MediaType -> MediaHandler -> Bool -> SQL.Statement () ResultSet
prepareRead qi selectQuery countQuery countTotal mt handler =
  SQL.dynamicallyParameterized (mtSnippet mt snippet) decodeIt
 where
  snippet =
    "WITH " <> sourceCTE <> " AS ( " <> selectQuery <> " ) " <>
    countCTEF <> " " <>
    "SELECT " <>
      countResultF <> " AS total_result_set, " <>
      "pg_catalog.count(_postgrest_t) AS page_total, " <>
      handlerF Nothing qi handler <> " AS body, " <>
      responseHeadersF <> " AS response_headers, " <>
      responseStatusF <> " AS response_status, " <>
      "''" <> " AS response_inserted " <>
    "FROM ( SELECT * FROM " <> sourceCTE <> " ) _postgrest_t"

  (countCTEF, countResultF) = countF countQuery countTotal

  decodeIt :: HD.Result ResultSet
  decodeIt = case mt of
    MTVndPlan{} -> planRow
    _           -> HD.singleRow $ standardRow True

prepareCall :: QualifiedIdentifier -> Routine -> SQL.Snippet -> SQL.Snippet -> SQL.Snippet -> Bool ->
               MediaType -> MediaHandler -> Bool ->
               SQL.Statement () ResultSet
prepareCall qi rout callProcQuery selectQuery countQuery countTotal mt handler =
  SQL.dynamicallyParameterized (mtSnippet mt snippet) decodeIt
  where
    snippet =
      "WITH " <> sourceCTE <> " AS (" <> callProcQuery <> ") " <>
      countCTEF <>
      "SELECT " <>
        countResultF <> " AS total_result_set, " <>
        (if funcReturnsSingle rout
          then "1"
          else "pg_catalog.count(_postgrest_t)") <> " AS page_total, " <>
        handlerF (Just rout) qi handler <> " AS body, " <>
        responseHeadersF <> " AS response_headers, " <>
        responseStatusF <> " AS response_status, " <>
        "''" <> " AS response_inserted " <>
      "FROM (" <> selectQuery <> ") _postgrest_t"

    (countCTEF, countResultF) = countF countQuery countTotal

    decodeIt :: HD.Result ResultSet
    decodeIt = case mt of
      MTVndPlan{} -> planRow
      _           -> fromMaybe (RSStandard (Just 0) 0 mempty mempty Nothing Nothing Nothing) <$> HD.rowMaybe (standardRow True)

preparePlanRows :: SQL.Snippet -> Bool -> SQL.Statement () (Maybe Int64)
preparePlanRows countQuery =
  SQL.dynamicallyParameterized snippet decodeIt
  where
    snippet = explainF PlanJSON mempty countQuery
    decodeIt :: HD.Result (Maybe Int64)
    decodeIt =
      let row = HD.singleRow $ column HD.bytea in
      (^? L.nth 0 . L.key "Plan" .  L.key "Plan Rows" . L._Integral) <$> row

standardRow :: Bool -> HD.Row ResultSet
standardRow noLocation =
  RSStandard <$> nullableColumn HD.int8 <*> column HD.int8
             <*> (if noLocation then pure mempty else fmap splitKeyValue <$> arrayColumn HD.bytea)
             <*> (fromMaybe mempty <$> nullableColumn HD.bytea)
             <*> nullableColumn HD.bytea
             <*> nullableColumn HD.text
             <*> nullableColumn HD.int8
  where
    splitKeyValue :: ByteString -> (ByteString, ByteString)
    splitKeyValue kv =
      let (k, v) = BS.break (== '=') kv in
      (k, BS.tail v)

mtSnippet :: MediaType -> SQL.Snippet -> SQL.Snippet
mtSnippet mediaType snippet = case mediaType of
  MTVndPlan _ fmt opts -> explainF fmt opts snippet
  _                    -> snippet

-- | We use rowList because when doing EXPLAIN (FORMAT TEXT), the result comes as many rows. FORMAT JSON comes as one.
planRow :: HD.Result ResultSet
planRow = RSPlan . BS.unlines <$> HD.rowList (column HD.bytea)

column :: HD.Value a -> HD.Row a
column = HD.column . HD.nonNullable

nullableColumn :: HD.Value a -> HD.Row (Maybe a)
nullableColumn = HD.column . HD.nullable

arrayColumn :: HD.Value a -> HD.Row [a]
arrayColumn = column . HD.listArray . HD.nonNullable
