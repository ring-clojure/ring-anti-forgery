(ns ring.middleware.anti-forgery
  "Ring middleware to prevent CSRF attacks."
  (:require [clojure.string :as str]
            [ring.middleware.anti-forgery.strategy :as strategy]
            [ring.middleware.anti-forgery.session :as session]))

(def ^{:doc "Binding that stores an anti-forgery token that must be included
            in POST forms or in HTTP headers if the handler is wrapped in the
            wrap-anti-forgery middleware.

            The default session strategy stores the token directly,
            but other strategies may wrap the token in a delay if the
            token is expensive to compute. The var should therefore be
            realized with clojure.core/force before use."
       :dynamic true}
  *anti-forgery-token*)

(defn- form-params [request]
  (merge (:form-params request)
         (:multipart-params request)))

(defn- default-request-token [request]
  (or (-> request form-params (get "__anti-forgery-token"))
      (-> request :headers (get "x-csrf-token"))
      (-> request :headers (get "x-xsrf-token"))))

(defn- get-request? [{method :request-method}]
  (or (= method :head)
      (= method :get)
      (= method :options)))

(defn- valid-request? [strategy request read-token safe-header]
  (or (get-request? request)
      (when safe-header
        (not (str/blank? (get-in request [:headers safe-header]))))
      (when-let [token (read-token request)]
        (strategy/valid-token? strategy request token))))

(def ^:private default-error-response
  {:status  403
   :headers {"Content-Type" "text/html"}
   :body    "<h1>Invalid anti-forgery token</h1>"})

(defn- constant-handler [response]
  (fn
    ([_] response)
    ([_ respond _] (respond response))))

(defn- make-error-handler [options]
  (or (:error-handler options)
      (constant-handler (:error-response options default-error-response))))

(defn wrap-anti-forgery
  "Middleware that prevents CSRF attacks. Any POST request to the handler
  returned by this function must contain a valid anti-forgery token, or else an
  access-denied response is returned.

  The anti-forgery token can be placed into a HTML page via the
  *anti-forgery-token* var, which is bound to a (possibly deferred) token.
  The token is also available in the request under
  `:anti-forgery-token`.

  By default, the token is expected to be POSTed in a form field named
  '__anti-forgery-token', or in the 'X-CSRF-Token' or 'X-XSRF-Token'
  headers.

  Accepts the following options:

  :read-token     - a function that takes a request and returns an anti-forgery
                    token, or nil if the token does not exist

  :error-response - the response to return if the anti-forgery token is
                    incorrect or missing

  :error-handler  - a handler function to call if the anti-forgery token is
                    incorrect or missing

  :safe-header    - a header that, if found on the request, will make this
                    middleware treat the request as safe without the need for
                    a valid anti-forgery token

  :strategy       - a strategy for creating and validating anti-forgety tokens,
                    which must satisfy the
                    ring.middleware.anti-forgery.strategy/Strategy protocol
                    (defaults to the session strategy:
                    ring.middleware.anti-forgery.session/session-strategy)

  Only one of :error-response, :error-handler may be specified."
  ([handler]
   (wrap-anti-forgery handler {}))
  ([handler options]
   {:pre [(not (and (:error-response options) (:error-handler options)))]}
   (let [read-token    (:read-token options default-request-token)
         strategy      (:strategy options (session/session-strategy))
         error-handler (make-error-handler options)
         safe-header   (some-> (:safe-header options) str/lower-case)]
     (fn
       ([request]
        (if (valid-request? strategy request read-token safe-header)
          (let [token (strategy/get-token strategy request)]
            (binding [*anti-forgery-token* token]
              (when-let [response (handler (assoc request :anti-forgery-token token))]
                (strategy/write-token strategy request response token))))
          (error-handler request)))
       ([request respond raise]
        (if (valid-request? strategy request read-token safe-header)
          (let [token (strategy/get-token strategy request)]
            (binding [*anti-forgery-token* token]
              (handler (assoc request :anti-forgery-token token)
                       #(respond
                         (when %
                           (strategy/write-token strategy request % token)))
                       raise)))
          (error-handler request respond raise)))))))
