(ns ring.middleware.test.anti-forgery
  (:require [clojure.test :refer :all]
            [ring.middleware.anti-forgery :as af :refer :all]
            [ring.middleware.anti-forgery.strategy :as strategy]
            [ring.middleware.anti-forgery.session :as session]
            [ring.mock.request :as mock]))

(deftest forgery-protection-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler  (wrap-anti-forgery (constantly response))]
    (are [status req] (= (:status (handler req)) status)
      403 (-> (mock/request :post "/")
              (assoc :form-params {"__anti-forgery-token" "foo"}))
      403 (-> (mock/request :post "/")
              (assoc :session {::af/anti-forgery-token "foo"})
              (assoc :form-params {"__anti-forgery-token" "bar"}))
      200 (-> (mock/request :post "/")
              (assoc :session {::af/anti-forgery-token "foo"})
              (assoc :form-params {"__anti-forgery-token" "foo"})))))

(deftest request-method-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler  (wrap-anti-forgery (constantly response))]
    (are [status req] (= (:status (handler req)) status)
      200 (mock/request :head "/")
      200 (mock/request :get "/")
      200 (mock/request :options "/")
      403 (mock/request :post "/")
      403 (mock/request :put "/")
      403 (mock/request :patch "/")
      403 (mock/request :delete "/"))))

(deftest csrf-header-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler  (wrap-anti-forgery (constantly response))
        sess-req (-> (mock/request :post "/")
                     (assoc :session {::af/anti-forgery-token "foo"}))]
    (are [status req] (= (:status (handler req)) status)
      200 (assoc sess-req :headers {"x-csrf-token" "foo"})
      200 (assoc sess-req :headers {"x-xsrf-token" "foo"}))))

(deftest multipart-form-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler  (wrap-anti-forgery (constantly response))]
    (is (= (-> (mock/request :post "/")
               (assoc :session {::af/anti-forgery-token "foo"})
               (assoc :multipart-params {"__anti-forgery-token" "foo"})
               handler
               :status)
           200))))

(deftest token-in-session-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler  (wrap-anti-forgery (constantly response))]
    (is (contains? (:session (handler (mock/request :get "/")))
                   ::af/anti-forgery-token))
    (is (not= (get-in (handler (mock/request :get "/"))
                      [:session ::af/anti-forgery-token])
              (get-in (handler (mock/request :get "/"))
                      [:session ::af/anti-forgery-token])))))

(deftest token-binding-test
  (letfn [(handler [request]
            {:status 200
             :headers {}
             :body *anti-forgery-token*})]
    (let [response ((wrap-anti-forgery handler) (mock/request :get "/"))]
      (is (= (get-in response [:session ::af/anti-forgery-token])
             (:body response))))))

(deftest nil-response-test
  (letfn [(handler [request] nil)]
    (let [response ((wrap-anti-forgery handler) (mock/request :get "/"))]
      (is (nil? response)))))

(deftest no-lf-in-token-test
  (letfn [(handler [request]
            {:status 200
             :headers {}
             :body *anti-forgery-token*})]
    (let [response ((wrap-anti-forgery handler) (mock/request :get "/"))
          token    (get-in response [:session ::af/anti-forgery-token])]
      (is (not (.contains token "\n"))))))

(deftest single-token-per-session-test
  (let [expected {:status 200, :headers {}, :body "Foo"}
        handler  (wrap-anti-forgery (constantly expected))
        actual   (handler
                  (-> (mock/request :get "/")
                      (assoc-in [:session ::af/anti-forgery-token] "foo")))]
    (is (= actual expected))))

(deftest not-overwrite-session-test
  (let [response {:status 200 :headers {} :body nil}
        handler  (wrap-anti-forgery (constantly response))
        session  (:session (handler (-> (mock/request :get "/")
                                        (assoc-in [:session "foo"] "bar"))))]
    (is (contains? session ::af/anti-forgery-token))
    (is (= (session "foo") "bar"))))

(deftest session-response-test
  (let [response {:status 200 :headers {} :session {"foo" "bar"} :body nil}
        handler  (wrap-anti-forgery (constantly response))
        session  (:session (handler (mock/request :get "/")))]
    (is (contains? session ::af/anti-forgery-token))
    (is (= (session "foo") "bar"))))

(deftest session-in-response-does-not-destroy-token-test
  (let [handler    (wrap-anti-forgery (fn [req]
                                        {:status  200
                                         :headers {}
                                         :session {"resp" "foo"}
                                         :body    nil}))
        valid-post (-> (mock/request :post "/")
                       (assoc :session {"req"                   "foo"
                                        ::af/anti-forgery-token "foo"})
                       (assoc :headers {"x-csrf-token" "foo"}))]
    (is (= (:session (handler valid-post))
           {::af/anti-forgery-token "foo"
            "resp"                  "foo"}))))

(deftest custom-error-response-test
  (let [response   {:status 200, :headers {}, :body "Foo"}
        error-resp {:status 500, :headers {}, :body "Bar"}
        handler    (wrap-anti-forgery (constantly response)
                                      {:error-response error-resp})]
    (is (= (dissoc (handler (mock/request :get "/")) :session)
           response))
    (is (= (dissoc (handler (mock/request :post "/")) :session)
           error-resp))))

(deftest custom-error-handler-test
  (let [response   {:status 200, :headers {}, :body "Foo"}
        error-resp {:status 500, :headers {}, :body "Bar"}
        handler    (wrap-anti-forgery (constantly response)
                                      {:error-handler (fn [request] error-resp)})]
    (is (= (dissoc (handler (mock/request :get "/")) :session)
           response))
    (is (= (dissoc (handler (mock/request :post "/")) :session)
           error-resp))))

(deftest disallow-both-error-response-and-error-handler
  (is (thrown?
        AssertionError
        (wrap-anti-forgery (constantly {:status 200})
                           {:error-handler (fn [request] {:status 500 :body "Handler"})
                            :error-response {:status 500 :body "Response"}}))))

(deftest custom-read-token-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler  (wrap-anti-forgery
                  (constantly response)
                  {:read-token #(get-in % [:headers "x-forgery-token"])})
        req      (-> (mock/request :post "/")
                     (assoc :session {::af/anti-forgery-token "foo"})
                     (assoc :headers {"x-forgery-token" "foo"}))]
    (is (= (:status (handler req))
           200))
    (is (= (:status (handler (assoc req :headers {"x-csrf-token" "foo"})))
           403))))

(deftest random-tokens-test
  (let [handler      (fn [_] {:status 200, :headers {}, :body *anti-forgery-token*})
        get-response (fn [] ((wrap-anti-forgery handler) (mock/request :get "/")))
        tokens       (map :body (repeatedly 1000 get-response))]
    (is (every? #(re-matches #"[A-Za-z0-9+/]{80}" %) tokens))
    (is (= (count tokens) (count (set tokens))))))

(deftest forgery-protection-cps-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler  (wrap-anti-forgery (fn [_ respond _] (respond response)))]

    (testing "missing token"
      (let [req  (-> (mock/request :post "/")
                     (assoc :form-params {"__anti-forgery-token" "foo"}))
            resp (promise)
            ex   (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 403))))

    (testing "valid token"
      (let [req  (-> (mock/request :post "/")
                     (assoc :session {::af/anti-forgery-token "foo"})
                     (assoc :form-params {"__anti-forgery-token" "foo"}))
            resp (promise)
            ex   (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 200))))))
