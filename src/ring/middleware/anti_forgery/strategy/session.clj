(ns ring.middleware.anti-forgery.strategy.session
  (:require [crypto.equality :as crypto]
            [crypto.random :as random]))

;; Implements a synchronizer token pattern, see https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Synchronizer_.28CSRF.29_Tokens


(defn- new-token []
  (random/base64 60))

(defn- session-token [request]
  (get-in request [:session ::ring.middleware.anti-forgery/anti-forgery-token]))



(defn- find-or-create-token [request]
  (or (session-token request) (new-token)))

(defn- valid-token? [request read-token]
  (let [user-token (read-token request)
        stored-token (session-token request)]
    (and user-token
         stored-token
         (crypto/eq? user-token stored-token))))

(defn- add-session-token [response request token]
  (if response
    (let [old-token (session-token request)]
      (if (= old-token token)
        response
        (-> response
            (assoc :session (:session response (:session request)))
            (assoc-in [:session ::ring.middleware.anti-forgery/anti-forgery-token] token))))))

(def session-sms
  {:valid-token          valid-token?
   :find-or-create-token find-or-create-token
   :wrap-response        add-session-token})