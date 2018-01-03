(ns ring.middleware.anti-forgery.strategy.session
  (:require [ring.middleware.anti-forgery.strategy :as strategy]
            [crypto.equality :as crypto]
            [crypto.random :as random]))

;; Implements a synchronizer token pattern, see https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Synchronizer_.28CSRF.29_Tokens


(defn- new-token []
  (random/base64 60))

(defn- session-token [request]
  (get-in request [:session ::ring.middleware.anti-forgery/anti-forgery-token]))


(defn- add-session-token [response request token]
  (if response
    (let [old-token (session-token request)]
      (if (= old-token token)
        response
        (-> response
            (assoc :session (:session response (:session request)))
            (assoc-in [:session ::ring.middleware.anti-forgery/anti-forgery-token] token))))))

(deftype SessionSMS []
  strategy/StateManagementStrategy
  (valid-token? [_ request read-token]
    (let [user-token (read-token request)
          stored-token (session-token request)]
      (and user-token
           stored-token
           (crypto/eq? user-token stored-token))))
  (find-or-create-token [_ request]
    (or (session-token request) (new-token)))
  (wrap-response [_ response request token]
    (add-session-token response request token)))