import java.security.Key;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jws.EcdsaUsingShaAlgorithm;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwx.CompactSerializer;
import org.junit.Assert;
import org.junit.Test;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

public class TokenValidatorTest
{
   // token and jwk produced by local keycloak
   String token =
         "eyJhbGciOiJFUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhTUlEWWhuTl9DekE4c2xxSDlfQTJ1cmxfeDNBajVMZjhpQlYyLWx0ZWZvIn0.eyJqdGkiOiJhZTY1NjBhMy0zYTU3LTQ2NWQtYmZkZS1hNDJkYTVjNThiNTYiLCJleHAiOjE1ODIxMDYzMzAsIm5iZiI6MCwiaWF0IjoxNTUwNTcwMzMwLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjIwNDAyL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIxYmYwNmNhOS04Y2ViLTQzNjAtYjhmYy04MjhjNjBhYzI4ZGEiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJFTVBJQyIsImF1dGhfdGltZSI6MTU1MDU3MDMzMCwic2Vzc2lvbl9zdGF0ZSI6ImI1Zjg5NDJmLThmM2ItNDY5MC04MDA4LTBmNzgwMDhjN2RmMyIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIGV4dGVybmFsLWlkIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJGcmVkIE9wb3NzdW0iLCJleHRlcm5hbElkIjoidGVzdCIsInByZWZlcnJlZF91c2VybmFtZSI6ImZyZWQub3Bvc3N1bS4xMDIxMiIsImdpdmVuX25hbWUiOiJGcmVkIiwiZmFtaWx5X25hbWUiOiJPcG9zc3VtIiwiZW1haWwiOiJmLm9wb3NzdW1AZ214LmRlIn0.MEUCIQCkqrf-FwOitf5vTcCHzOISOAB978ozuhiMLhp3u-3i9gIgSZlRJQqtK6XWJd_KoUA_7O8UrDZ-olZsHCB4ivZUYj0";
   String jwk = "{\"kid\":\"aMIDYhnN_CzA8slqH9_A2url_x3Aj5Lf8iBV2-ltefo\",\"kty\":\"EC\",\"alg\":\"ES256\",\"use\":\"sig\",\"crv\":\"P-256\",\"x\":\"ANraETptwbUJ1-9WvpJNdTCnTFK6uceWYUcPVfH3heDI\",\"y\":\"Jj1NjevefaTd9nZhQ-CRb2LDWwhqhrkCpajujQKSdlY\"}";

   String wrongJwk = jwk.replace("ANraE", "ABCDE");

   @Test
   public void testJose4jWithValidSignature() throws Exception
   {
      Assert.assertTrue(validateWithJose4jIsOk(token, jwk));
   }

   @Test
   public void testJose4jWithInvalidSignature() throws Exception
   {
      Assert.assertFalse(validateWithJose4jIsOk(token, wrongJwk));
   }

   @Test
   public void testJasonWebTokenWithValidSignature()
   {
      Assert.assertTrue(validateWithJasonWebTokenIsOk(token, jwk));
   }

   @Test
   public void testJasonWebTokenWithInvalidSignature()
   {
      Assert.assertFalse(validateWithJasonWebTokenIsOk(token, wrongJwk));
   }

   private static boolean validateWithJasonWebTokenIsOk(String token, String jwk)
   {
      try
      {
         JwtParser parser = Jwts.parser();
         parser.setSigningKey(buildKey(jwk));
         parser.parse(token);
      }
      catch (Exception e)
      {
         return false;
      }
      return true;
   }

   private static boolean validateWithJose4jIsOk(String token, String jwk) throws Exception
   {
      try
      {
         // take keycloak's incorrectly formatted signature (ASN.1 DER) and convert it to the JWS/JWA standard format (concatenated R & S)
         String[] parts = CompactSerializer.deserialize(token);
         byte[] signatureBytesDer = Base64Url.decode(parts[2]);
         byte[] signatureBytesConcat = EcdsaUsingShaAlgorithm.convertDerToConcatenated(signatureBytesDer, 64);
         token = CompactSerializer.serialize(parts[0], parts[1], Base64Url.encode(signatureBytesConcat));

         new JwtConsumerBuilder()
               .setVerificationKey(buildKey(jwk))
               .setSkipAllDefaultValidators()
               .build().process(token);
      }
      catch (InvalidJwtException  e)
      {
         if (e.hasErrorCode(ErrorCodes.SIGNATURE_INVALID))
         {
            return false;
         }
         throw e;
      }
      return true;
   }

   private static Key buildKey(String jwkJson)
   {
      try
      {
         return EllipticCurveJsonWebKey.Factory.newPublicJwk(jwkJson).getKey();
      }
      catch (Exception e)
      {
         throw new RuntimeException("Could not create jwk from string", e);
      }
   }
}
