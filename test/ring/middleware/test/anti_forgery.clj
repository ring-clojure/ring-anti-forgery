(ns ring.middleware.test.anti-forgery
  (:require [ring.middleware.anti-forgery :as af]
            [ring.middleware.anti-forgery.strategy.encrypted-token :as encrypted-token]
            [buddy.core.keys :as keys]
            [clj-time.core :as time])
  (:use clojure.test
        ring.middleware.anti-forgery
        ring.mock.request))

(def ^:private create-encrypted-csrf-token #'ring.middleware.anti-forgery.strategy.encrypted-token/create-encrypted-csrf-token)

(def ^:private pubkey (keys/public-key "dev-resources/test-certs/pubkey.pem"))
(def ^:private privkey (keys/private-key "dev-resources/test-certs/privkey.pem" "antiforgery"))
(def ^:private secret "secret-to-validate-token-after-decryption-to-make-sure-i-encrypted-stuff")
(def ^:private expires-in-one-hour (time/hours 1))

(def ^:private encrypted-token-sms (encrypted-token/encrypted-token-sms pubkey privkey expires-in-one-hour secret))

(def ^:private encrypted-token-options {:state-management-strategy encrypted-token-sms})

(defn- status=* [handler status req]
  (= status (:status (handler req))))


(deftest forgery-protection-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response))]
    (are [status req] (= (:status (handler req)) status)
                      403 (-> (request :post "/")
                              (assoc :form-params {"__anti-forgery-token" "foo"}))
                      403 (-> (request :post "/")
                              (assoc :session {::af/anti-forgery-token "foo"})
                              (assoc :form-params {"__anti-forgery-token" "bar"}))
                      200 (-> (request :post "/")
                              (assoc :session {::af/anti-forgery-token "foo"})
                              (assoc :form-params {"__anti-forgery-token" "foo"})))))

(deftest forgery-protection-via-encrypted-token-test
  (let [expired-one-hour-ago (time/hours -1)

        response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response) encrypted-token-options)
        status= (partial status=* handler)]

    (testing "without anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/"))))

    (testing "with non-decryptable anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                ;; anti-forgery-token not decryptable with our key
                                (assoc :form-params {"__anti-forgery-token" "bar"}))))
    (testing "with anti-forgery-token containing wrong secret"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                ;; anti-forgery-token not decryptable with our key
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token pubkey (str "another-secret-" secret) expires-in-one-hour nil)}))))
    (testing "with expired anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                ;; anti-forgery-token not decryptable with our key
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token pubkey secret expired-one-hour-ago nil)}))))
    (testing "with correct anti-forgery-token. (Attention: Has different nounce, but that's ok)"
      (are [status req] (status= status req)
                        200 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token pubkey secret expires-in-one-hour nil)}))))))



(deftest request-method-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response))]
    (are [status req] (= (:status (handler req)) status)
                      200 (request :head "/")
                      200 (request :get "/")
                      200 (request :options "/")
                      403 (request :post "/")
                      403 (request :put "/")
                      403 (request :patch "/")
                      403 (request :delete "/"))))

(deftest request-method-via-encrypted-token-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response) encrypted-token-options)]
    (are [status req] (= (:status (handler req)) status)
                      200 (request :head "/")
                      200 (request :get "/")
                      200 (request :options "/")
                      403 (request :post "/")
                      403 (request :put "/")
                      403 (request :patch "/")
                      403 (request :delete "/"))))

(deftest csrf-header-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response))
        sess-req (-> (request :post "/")
                     (assoc :session {::af/anti-forgery-token "foo"}))]
    (are [status req] (= (:status (handler req)) status)
                      200 (assoc sess-req :headers {"x-csrf-token" "foo"})
                      200 (assoc sess-req :headers {"x-xsrf-token" "foo"}))))

(deftest multipart-form-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response))]
    (is (= (-> (request :post "/")
               (assoc :session {::af/anti-forgery-token "foo"})
               (assoc :multipart-params {"__anti-forgery-token" "foo"})
               handler
               :status)
           200))))

(deftest token-in-session-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response))]
    (is (contains? (:session (handler (request :get "/")))
                   ::af/anti-forgery-token))
    (is (not= (get-in (handler (request :get "/"))
                      [:session ::af/anti-forgery-token])
              (get-in (handler (request :get "/"))
                      [:session ::af/anti-forgery-token])))))

(deftest token-binding-test
  (letfn [(handler [request]
            {:status  200
             :headers {}
             :body    *anti-forgery-token*})]
    (let [response ((wrap-anti-forgery handler) (request :get "/"))]
      (is (= (get-in response [:session ::af/anti-forgery-token])
             (:body response))))))

(defn- valid-encrypted-token? [private-key secret token]
  (#'ring.middleware.anti-forgery.strategy.encrypted-token/valid-token? private-key secret token identity))

(deftest token-binding-via-encrypted-token-test
  (letfn [(handler [request]
            {:status  200
             :headers {}
             :body    *anti-forgery-token*})]
    (let [response ((wrap-anti-forgery handler encrypted-token-options) (request :get "/"))]
      (is (valid-encrypted-token? privkey secret (:body response))))))

(deftest nil-response-test
  (letfn [(handler [request] nil)]
    (let [response ((wrap-anti-forgery handler) (request :get "/"))]
      (is (nil? response)))))

(deftest no-lf-in-token-test
  (letfn [(handler [request]
            {:status  200
             :headers {}
             :body    *anti-forgery-token*})]
    (let [response ((wrap-anti-forgery handler) (request :get "/"))
          token (get-in response [:session ::af/anti-forgery-token])]
      (is (not (.contains token "\n"))))))

(deftest single-token-per-session-test
  (let [expected {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly expected))
        actual (handler
                 (-> (request :get "/")
                     (assoc-in [:session ::af/anti-forgery-token] "foo")))]
    (is (= actual expected))))

(deftest not-overwrite-session-test
  (let [response {:status 200 :headers {} :body nil}
        handler (wrap-anti-forgery (constantly response))
        session (:session (handler (-> (request :get "/")
                                       (assoc-in [:session "foo"] "bar"))))]
    (is (contains? session ::af/anti-forgery-token))
    (is (= (session "foo") "bar"))))

(deftest session-response-test
  (let [response {:status 200 :headers {} :session {"foo" "bar"} :body nil}
        handler (wrap-anti-forgery (constantly response))
        session (:session (handler (request :get "/")))]
    (is (contains? session ::af/anti-forgery-token))
    (is (= (session "foo") "bar"))))

(deftest no-session-response-via-encrypted-token-test
  (let [response {:status 200 :headers {} :session {"foo" "bar"} :body nil}
        handler (wrap-anti-forgery (constantly response) encrypted-token-options)
        session (:session (handler (request :get "/")))]
    (is (not (contains? session ::af/anti-forgery-token)))
    (is (= (session "foo") "bar"))))

(deftest custom-error-response-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        error-resp {:status 500, :headers {}, :body "Bar"}
        handler (wrap-anti-forgery (constantly response)
                                   {:error-response error-resp})]
    (is (= (dissoc (handler (request :get "/")) :session)
           response))
    (is (= (dissoc (handler (request :post "/")) :session)
           error-resp))))

(deftest custom-error-handler-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        error-resp {:status 500, :headers {}, :body "Bar"}
        handler (wrap-anti-forgery (constantly response)
                                   {:error-handler (fn [request] error-resp)})]
    (is (= (dissoc (handler (request :get "/")) :session)
           response))
    (is (= (dissoc (handler (request :post "/")) :session)
           error-resp))))

(deftest disallow-both-error-response-and-error-handler
  (is (thrown?
        AssertionError
        (wrap-anti-forgery (constantly {:status 200})
                           {:error-handler  (fn [request] {:status 500 :body "Handler"})
                            :error-response {:status 500 :body "Response"}}))))

(deftest custom-read-token-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery
                  (constantly response)
                  {:read-token #(get-in % [:headers "x-forgery-token"])})
        req (-> (request :post "/")
                (assoc :session {::af/anti-forgery-token "foo"})
                (assoc :headers {"x-forgery-token" "foo"}))]
    (is (= (:status (handler req))
           200))
    (is (= (:status (handler (assoc req :headers {"x-csrf-token" "foo"})))
           403))))

(deftest random-tokens-test
  (let [handler (fn [_] {:status 200, :headers {}, :body *anti-forgery-token*})
        get-response (fn [] ((wrap-anti-forgery handler) (request :get "/")))
        tokens (map :body (repeatedly 1000 get-response))]
    (is (every? #(re-matches #"[A-Za-z0-9+/]{80}" %) tokens))
    (is (= (count tokens) (count (set tokens))))))

(deftest forgery-protection-cps-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (fn [_ respond _] (respond response)))]

    (testing "missing token"
      (let [req (-> (request :post "/")
                    (assoc :form-params {"__anti-forgery-token" "foo"}))
            resp (promise)
            ex (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 403))))

    (testing "valid token"
      (let [req (-> (request :post "/")
                    (assoc :session {::af/anti-forgery-token "foo"})
                    (assoc :form-params {"__anti-forgery-token" "foo"}))
            resp (promise)
            ex (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 200))))))



(deftest forgery-protection-cps-via-encrypted-token-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (fn [_ respond _] (respond response)) encrypted-token-options)]

    (testing "missing token"
      (let [req (-> (request :post "/")
                    (assoc :form-params {"__anti-forgery-token" "foo"}))
            resp (promise)
            ex (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 403))))

    (testing "valid token"
      (let [req (-> (request :post "/")
                    (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token pubkey secret expires-in-one-hour nil)}))
            resp (promise)
            ex (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 200))))))