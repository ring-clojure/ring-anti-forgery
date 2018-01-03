(ns ring.middleware.anti-forgery.strategy.encrypted-token
  (:require [ring.middleware.anti-forgery.strategy :as strategy]
            [clj-time.core :as time]
            [buddy.sign.jwt :as jwt]
            [crypto.equality :as crypto])
  (:import (clojure.lang ExceptionInfo)))

(def ^:private crypt-options {:alg :rsa-oaep
                              :enc :a128cbc-hs256})



(deftype EncryptedTokenSMS [public-key private-key expiration-period stored-secret]
  strategy/StateManagementStrategy
  (valid-token? [_ request read-token]
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
  (find-or-create-token [_ _]
    (jwt/encrypt {:nonce   (crypto.random/base64 256)
                  :secret  stored-secret
                  :expires (clj-time.coerce/to-long
                             (time/plus (time/now)
                                        expiration-period))}
                 public-key
                 crypt-options))
  (wrap-response [_ response request token]
    response))