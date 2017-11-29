(defproject ring/ring-anti-forgery "1.1.0"
  :description "Ring middleware to prevent CSRF attacks"
  :url "https://github.com/ring-clojure/ring-anti-forgery"
  :license {:name "The MIT License"
            :url  "http://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [crypto-random "1.2.0"]
                 [crypto-equality "1.0.0"]
                 [hiccup "1.0.5"]
                 [clj-time "0.14.2"]
                 [buddy/buddy-core "1.4.0"]
                 [buddy/buddy-sign "2.2.0"]]
  :aliases {"test-all" ["with-profile" "default:+1.7:+1.8:+1.9" "test"]}
  :profiles
  {:dev {:dependencies [[ring/ring-mock "0.3.0"]]}
   :1.7 {:dependencies [[org.clojure/clojure "1.7.0"]]}
   :1.8 {:dependencies [[org.clojure/clojure "1.8.0"]]}
   :1.9 {:dependencies [[org.clojure/clojure "1.9.0-alpha11"]]}})
