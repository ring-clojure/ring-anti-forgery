(ns ring.middleware.anti-forgery.strategy)

(defprotocol StateManagementStrategy
  (valid-token? [this request read-token])
  (find-or-create-token [this request])
  (wrap-response [this response request token]))
