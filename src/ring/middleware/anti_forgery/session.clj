(ns ring.middleware.anti-forgery.session
  "Contains the synchronizer token (or session) strategy."
  (:require [ring.middleware.anti-forgery.strategy :as strategy]
            [crypto.equality :as crypto]))

(defn- random-base64 [buffer-size]
  (let [random (java.security.SecureRandom.)
        base64 (.withoutPadding (java.util.Base64/getEncoder))
        buffer (byte-array buffer-size)]
    (.nextBytes random buffer)
    (.encodeToString base64 buffer)))

(defn- session-token [request]
  (get-in request [:session :ring.middleware.anti-forgery/anti-forgery-token]))

(deftype SessionStrategy []
  strategy/Strategy
  (get-token [this request]
    (or (session-token request)
        (random-base64 60)))

  (valid-token? [_ request token]
    (when-let [stored-token (session-token request)]
      (crypto/eq? token stored-token)))

  (write-token [this request response token]
    (let [old-token (session-token request)]
      (if (= old-token token)
        response
        (-> response
            (assoc :session (:session response (:session request)))
            (assoc-in
              [:session :ring.middleware.anti-forgery/anti-forgery-token]
              token))))))

(defn session-strategy
  "Implements a synchronizer token pattern strategy, suitable for passing to
  the :strategy option in the ring.middleware.anti-forgery/wrap-anti-forgery
  middleware.

  See https://goo.gl/WRm7Kp for more information about this pattern."
  []
  (->SessionStrategy))
