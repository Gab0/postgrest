{-|
Module      : PostgREST.AuthSAML
Description : PostgREST SAML authentication functions.

This module provides functions to deal with the SAML authentication.

-}
{-# OPTIONS_GHC -Wwarn=deprecations #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE LambdaCase #-}
module PostgREST.AuthSAML
  ( middleware
  ) where

import qualified Crypto.Hash           as H
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy  as BL
import Data.ByteString.UTF8 as BSU
    ( toString, fromString, ByteString )
import qualified Data.Cache            as C
import           Data.IORef            (newIORef, atomicModifyIORef)
import qualified Data.Map              as Map
import qualified Data.Text             as T
import           Data.String           (String)

import qualified Network.Wai.SAML2     as SAML2
import qualified Network.Wai.SAML2.Response as SAML2
import qualified Network.Wai.SAML2.Request  as SAML2

import qualified Network.Wai.SAML2.Validation as SAML2

import qualified Network.Wai           as Wai
import qualified Network.Wai.Parse     as Wai

import           Network.HTTP.Types    (status200, status401)

import           PostgREST.AppState    (AppState (..), SAML2State (..))

import           Protolude
import           Prelude               (lookup)

import           Network.Wai.SAML2.KeyInfo (KeyInfo(keyInfoCertificate))

-- | Different routes a request can take when handled by this middleware.
data RequestRoute = Login | Logout | Block | Pass

-- | Middleware for the SAML2 authentication.
-- NOTE: Here we block access to Postgres' login endpoint.
-- Could SQL function privileges alone protect the function from being called directly?
middleware :: AppState -> Wai.Middleware
middleware appState app req respond = do
  case stateSAML2 appState of
    -- No SAML2 configuration, just pass the request;
    Nothing -> app req respond
    -- SAML2 configuration found, let's handle the request;
    Just samlState ->
      case matchRequestRoute req samlState of
        -- Whether it is an actual login request or any other request
        -- will be decided downstream by the dedicated SAML2 middleware.
        Pass   -> app req respond
        Logout -> proceed Logout
        Login  -> proceed Login
        _      -> respond $ respondError "Unauthorized."

      where
        proceed r  = saml2Callback samlState r (handleSAMLLoginResult samlState) app req respond

-- | Match request action
matchRequestRoute :: Wai.Request -> SAML2State -> RequestRoute
matchRequestRoute req samlState
  | p == saml2LoginEndpointIn   samlState = Login
  | p == saml2LoginEndpointOut  samlState = Block
  | p == saml2LogoutEndpointIn  samlState = Logout
  | p == saml2LogoutEndpointOut samlState = Block
  | otherwise = Pass
  where
    p = T.pack $ BSU.toString $ Wai.rawPathInfo req

-- | Discard the request and respond with an error message.
respondError :: BL.ByteString -> Wai.Response
respondError = Wai.responseLBS
    status401
    [("Content-Type", "text/plain")]

-- | Respond with a SAML2 response.
_respondSAMLResponse :: BL.ByteString -> Wai.Response
_respondSAMLResponse = Wai.responseLBS
    status200
    [("Content-Type", "text/plain")]

-- | For every SAML authentication error,
-- we want to log it and respond with a generic error message
-- to avoid leaking security information.
handleSamlError :: String -> IO Wai.Response
handleSamlError err = do
  putStrLn $ ("SAML2 Error: " :: String) ++ show err
  pure $ respondError "SAML authentication error. Check the server logs."

-- | Converts the original request into a request to the login endpoint.
-- NOTE: This might not be the best idea.
-- The alternative is to create a proper PostgREST action to call the login RPC function.
rerouteRequestToAnotherEndpoint :: Wai.Request -> Text -> Map.Map Text Text -> IO Wai.Request
rerouteRequestToAnotherEndpoint req target_endpoint parameters = do

  newBody <- generateBody

  return req
    { Wai.requestHeaders = new_headers
    , Wai.requestBody = newBody
    , Wai.rawPathInfo = BSU.fromString $ T.unpack target_endpoint
    , Wai.pathInfo = filter (/= "") $ T.splitOn "/" target_endpoint
    , Wai.requestBodyLength = Wai.KnownLength
                            $ fromIntegral
                            $ S8.length rendered_form_data
    , Wai.requestMethod = "POST"
    }
  where
    new_headers = [("Content-Type", "application/x-www-form-urlencoded")]

    convert_parameters :: Map.Map Text Text -> Map.Map String String
    convert_parameters = Map.mapKeys T.unpack . Map.map T.unpack

    rendered_form_data = renderFormData $ convert_parameters parameters

    generateBody = do
      ichunks <- newIORef [rendered_form_data]
      let rbody = atomicModifyIORef ichunks $ \case
                 [] -> ([], S8.empty)
                 x:y -> (y, x)
      return rbody

-- | Convert a map of form data to a bytestring that can be used as a request body.
renderFormData :: Map.Map String String -> ByteString
renderFormData d = S8.pack $ intercalate "&" $ map renderPair $ Map.toList d
  where
    renderPair (k, v) = k ++ "=" ++ v

-- | Modifies the request according to the results from the SAML2 validation.
handleSAMLLoginResult :: SAML2State -> Either SAML2.SAML2Error SAML2.Result -> Wai.Middleware
handleSAMLLoginResult samlState result' app req respond =
  case result' of
    Left err -> respond =<< handleSamlError (show err)
    Right result -> do
      known_assertion <- tryRetrieveAssertionID samlState (SAML2.assertionId (SAML2.assertion result))
      if known_assertion
      then respond =<< handleSamlError "Replay attack detected."
      else do
          -- NOTE: SAML Authentication success!
          -- Now we pass all the SAML parameters to the JWT endpoint.
          let
            attributes = extractAttributes $ SAML2.assertion result

          putStrLn ("SAML parameters: " ++ show (Map.toList attributes) :: String)

          req' <- rerouteRequestToAnotherEndpoint req (saml2LoginEndpointOut samlState) attributes
          storeAssertionID samlState (SAML2.assertionId (SAML2.assertion result))
          app req' respond
  where
    _readCertificateFromSignature :: SAML2.Result -> Maybe Text
    _readCertificateFromSignature result = do
      keyInfo <- SAML2.signatureKeyInfo $ SAML2.responseSignature $ SAML2.response result
      return $ encodeCertificate $ keyInfoCertificate keyInfo

-- | Handle the SAML2 logout (SLO).
handleSAMLLogoutResult :: SAML2State -> Text -> Wai.Middleware
handleSAMLLogoutResult samlState username app req respond = do
  putStrLn $ "SAML Logout: " ++ show username
  req' <- rerouteRequestToAnotherEndpoint req (saml2LogoutEndpointOut samlState) $ Map.fromList [(T.pack "name_id", username)]
  app req' respond

-- | Encode a certificate to be used as a JWT parameter.
-- Here we encode it as SHA256 because passing the raw certificate
-- over requests will hit encoding issues.
encodeCertificate :: BSU.ByteString -> Text
encodeCertificate = T.pack
                  . show
                  . H.hashWith H.SHA256
                  . BSU.fromString
                  . T.unpack
                  . T.replace "\n" ""
                  . T.pack
                  . BSU.toString

-- | Extracts all relevant atrtibutes from the assertion.
-- This includes all assertion attribute statements along with the name id.
extractAttributes :: SAML2.Assertion -> Map Text Text
extractAttributes assertion' = Map.insert "name_id" name_id attributes
  where
    simplifyAttribute :: SAML2.AssertionAttribute -> (Text, Text)
    simplifyAttribute attr = (SAML2.attributeName attr, SAML2.attributeValue attr)

    attributes = Map.fromList
               $ map simplifyAttribute
               $ SAML2.assertionAttributeStatement assertion'

    name_id = SAML2.nameIDValue $ SAML2.subjectNameID $ SAML2.assertionSubject assertion'

-- | Checks if a given assertion ID is already known.
tryRetrieveAssertionID :: SAML2State -> Text -> IO Bool
tryRetrieveAssertionID samlState t =
  isJust <$> C.lookup (saml2KnownIds samlState) t

-- | Store a known assertion ID in the cache.
storeAssertionID :: SAML2State -> Text -> IO ()
storeAssertionID samlState t = C.insert (saml2KnownIds samlState) t ()

-- | Modified SAML2 callback handler.
saml2Callback :: SAML2State
              -> RequestRoute
              -> (Either SAML2.SAML2Error SAML2.Result -> Wai.Middleware)
              -> Wai.Middleware
saml2Callback samlState route callback app req sendResponse = do
  let failure = callback (Left SAML2.InvalidRequest) app req sendResponse

  case route of
    Pass -> app req sendResponse
    Block -> failure
    Login -> do
      body <- extractRequestBody req
      -- NOTE: lookup SAMLRequest too? (seems to not be the case)
      case lookup "SAMLResponse" body of
          Nothing -> failure
          Just val -> do
              let rs = lookup "RelayState" body
              result <- SAML2.validateResponse (saml2StateAppConfig samlState) val <&>
                            fmap (\(assertion, response) ->
                                      SAML2.Result {
                                          SAML2.assertion = assertion,
                                          SAML2.relayState = rs,
                                          SAML2.response = response
                                      })
              -- call the callback
              callback result app req sendResponse

    -- Here we handle the logout requests.
    --
    -- FIXME: Logout requests are not validated.
    -- The signature is not checked!
    Logout -> do
      body <- extractRequestBody req
      case lookup "SAMLRequest" body of
        -- The request does not contain the expected payload,
        Nothing -> failure
        Just val -> do
            content <- runExceptT $ SAML2.decodeResponse val
            case content of
              Left _ -> failure
              Right (_responseXmlDoc, samlRequest) -> do
                putStrLn $ "SAMLRequest: " ++ show samlRequest
                case SAML2.authnRequestNameID $ samlRequest of
                  Just nameID -> handleSAMLLogoutResult samlState (SAML2.nameIDValue nameID) app req sendResponse
                  Nothing -> handleSamlError "Logout request does not contain the username." >>= sendResponse

-- | Extracts the request body as a list of parameters.
extractRequestBody :: Wai.Request -> IO [Wai.Param]
extractRequestBody req = do
  -- default request parse options, but do not allow files;
  -- we are not expecting any
  let bodyOpts = Wai.setMaxRequestNumFiles 0
               $ Wai.setMaxRequestFileSize 0
                 Wai.defaultParseRequestBodyOptions

  -- parse the request
  (body, _) <- Wai.parseRequestBodyEx bodyOpts Wai.lbsBackEnd req
  return body
