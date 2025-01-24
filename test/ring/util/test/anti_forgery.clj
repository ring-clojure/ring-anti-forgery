(ns ring.util.test.anti-forgery
  (:require [clojure.test :refer :all]
            [ring.middleware.anti-forgery :refer [*anti-forgery-token*]]
            [ring.util.anti-forgery :refer :all]))

(deftest anti-forgery-field-test
  (binding [*anti-forgery-token* "abc"]
    (is (= (anti-forgery-field)
           (str "<input id=\"__anti-forgery-token\" name=\"__anti-forgery-token\""
                " type=\"hidden\" value=\"abc\" />"))))
  (binding [*anti-forgery-token* "<\"&"]
    (is (= (anti-forgery-field)
           (str "<input id=\"__anti-forgery-token\" name=\"__anti-forgery-token\""
                " type=\"hidden\" value=\"&lt;&quot;&amp;\" />")))))

