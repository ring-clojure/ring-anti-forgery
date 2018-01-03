(ns ring.middleware.anti-forgery.strategy.encrypted-token
  (:require [clj-time.core :as time]
            [buddy.sign.jwt :as jwt]
            [crypto.equality :as crypto])
  (:import (clojure.lang ExceptionInfo)))

(def ^:private crypt-options {:alg :rsa-oaep
                              :enc :a128cbc-hs256})


(defn- create-encrypted-csrf-token [public-key secret expires #_request _]
  (jwt/encrypt {:nonce   (crypto.random/base64 256)
                :secret  secret
                :expires (clj-time.coerce/to-long
                           (time/plus (time/now)
                                      expires))}
               public-key
               crypt-options))

(defn- valid-token? [private-key stored-secret request read-token]
  (when-let [token (read-token request)]
    (try
      (let [{:keys [secret expires]} (jwt/decrypt token
                                                  private-key
                                                  crypt-options)]
        (and
          (crypto/eq? secret stored-secret)
          (time/before? (time/now)
                        (clj-time.coerce/from-long expires))))
      (catch ExceptionInfo e
        false))))


(defn- wrap-response [response request token]
  response)


(defn encrypted-token-sms [public-key private-key expiration-period secret]
  {:valid-token          (partial valid-token? private-key secret)
   :find-or-create-token (partial create-encrypted-csrf-token public-key secret expiration-period)
   :wrap-response wrap-response
   })