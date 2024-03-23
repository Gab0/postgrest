
module PostgREST.SAMLState where


import           Crypto.PubKey.RSA.Types    (PublicKey)
import qualified Data.ByteString            (readFile)
import qualified Data.ByteString.UTF8       as UTF8
import qualified Data.Cache                 as C
import qualified Data.List                  as L
import qualified Data.Text                  as T
import           Data.String                (String)

import System.Environment                (lookupEnv)
import System.IO.Error                   (IOError)

import Network.Wai.SAML2  (SAML2Config (..), saml2ConfigNoEncryption)
import Network.Wai.SAML2.Validation      (readSignedCertificate, readPKCS12Certificate)

import PostgREST.Config (AppConfig(..), SAMLEndpoints(..), configSAMLEndpoints)

import Protolude

-- | Read and process the certificate loaded
-- from the environment variable
-- into a PublicKey.
-- This env var can be provided as a path to a
-- '.pem' file containing the certificate
-- or given as raw certificate data.
loadPublicKey :: Maybe String -> IO (Maybe PublicKey)
loadPublicKey Nothing = do
  putStrLn ("No SAML certificate provided." :: String)
  pure Nothing
loadPublicKey (Just rawKeyFromEnv) = do

  keyFromEnv <- interpreteEnv rawKeyFromEnv
  password <- lookupEnv "POSTGREST_SAML_CERTIFICATE_PASSWORD"
  case keyFromEnv of
    Left err -> do
      putStrLn ("Failure to read the SAML certificate. " ++ show err :: String)
      pure Nothing
    Right key -> do
      -- Load the public key from the loaded certificate data.
      -- putStrLn ("Reading the SAML certificate from the environment... " ++ take 10 (show key) :: String)

      let (err, publicKeys) = partitionEithers [
              readSignedCertificate $ UTF8.toString key,
              readPKCS12Certificate key (UTF8.fromString <$> password)
            ]

      putStrLn (show err :: String)
      let publicKey = listToMaybe publicKeys
      -- putStrLn ("Loaded a public key: " ++ show publicKey :: String)

      pure publicKey
  where
    getExtension :: String -> Text
    getExtension = L.last . T.splitOn "." . T.pack

    interpreteEnv :: String -> IO (Either IOError ByteString)
    interpreteEnv raw =
      case getExtension raw of
        "pem" -> try $ Data.ByteString.readFile raw
        _     -> pure $ Right $ UTF8.fromString raw

data SAML2State = SAML2State
  { saml2StateAppConfig    :: SAML2Config
  -- | Known assertion IDs, so we can avoid 'replay' attacks.
  , saml2KnownIds          :: C.Cache Text ()
  , saml2Endpoints         :: SAMLEndpoints
  }

-- | The default SAML2 parameters.
standardSAML2State :: AppConfig -> IO SAML2State
standardSAML2State conf = do
  knownIds <- C.newCache Nothing :: IO (C.Cache Text ())

  putStrLn ("Trying to locate a SAML certificate in the environment." :: String)
  pubKey <- loadPublicKey =<< lookupEnv "POSTGREST_SAML_CERTIFICATE"

  pure $ SAML2State
    { saml2StateAppConfig = (saml2ConfigNoEncryption pubKey)
      { saml2DisableTimeValidation = False }
    , saml2KnownIds = knownIds
    , saml2Endpoints = configSAMLEndpoints conf
    }
