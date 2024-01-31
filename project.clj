(defproject ring/ring-anti-forgery "1.3.0"
  :description "Ring middleware to prevent CSRF attacks"
  :url "https://github.com/ring-clojure/ring-anti-forgery"
  :license {:name "The MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.9.0"]
                 [crypto-random "1.2.1"]
                 [crypto-equality "1.0.1"]
                 [hiccup "1.0.5"]]
  :plugins [[lein-codox "0.10.8"]]
  :codox
  {:output-path "codox"
   :project     {:name "Ring Anti-Forgery"}
   :source-uri  "http://github.com/ring-clojure/ring-anti-forgery/blob/{version}/{filepath}#L{line}"}
  :aliases {"test-all" ["with-profile" "default:+1.8:+1.9:+1.10:+1.11" "test"]}
  :profiles
  {:dev  {:dependencies [[ring/ring-mock "0.4.0"]]}
   :1.8  {:dependencies [[org.clojure/clojure "1.8.0"]]}
   :1.9  {:dependencies [[org.clojure/clojure "1.9.0"]]}
   :1.10 {:dependencies [[org.clojure/clojure "1.10.3"]]}
   :1.11 {:dependencies [[org.clojure/clojure "1.11.1"]]}})
