# unlimited-jce-security-policy

[![Build Status](https://travis-ci.org/furplag/unlimited-jce-security-policy.svg?branch=master)](https://travis-ci.org/furplag/unlimited-jce-security-policy)
[![Coverage Status](https://coveralls.io/repos/github/furplag/unlimited-jce-security-policy/badge.svg?branch=master)](https://coveralls.io/github/furplag/unlimited-jce-security-policy?branch=master)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/22ae0bc020c745ccb9ac8a6b17bb101f)](https://www.codacy.com/app/furplag/unlimited-jce-security-policy?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=furplag/unlimited-jce-security-policy&amp;utm_campaign=Badge_Grade)
[![codebeat badge](https://codebeat.co/badges/35b07037-c0a4-4012-b5b8-397d203b9eaa)](https://codebeat.co/projects/github-com-furplag-unlimited-jce-security-policy-master)
[![Maintainability](https://api.codeclimate.com/v1/badges/28e7b02ed1d5e862145c/maintainability)](https://codeclimate.com/github/furplag/unlimited-jce-security-policy/maintainability)

turn "isRestricted" off JCE security policy ( the reason because I want to use AES_256 ) .

## Getting Start
Add the following snippet to any project's pom that depends on your project
```xml
<repositories>
  ...
  <repository>
    <id>unlimited-jce-security-policy</id>
    <url>https://raw.github.com/furplag/unlimited-jce-security-policy/mvn-repo/</url>
    <snapshots>
      <enabled>true</enabled>
      <updatePolicy>always</updatePolicy>
    </snapshots>
  </repository>
</repositories>
...
<dependencies>
  ...
  <dependency>
    <groupId>jp.furplag.sandbox</groupId>
    <artifactId>unlimited-jce-security-policy</artifactId>
    <version>2.0.0</version>
  </dependency>
</dependencies>
```

## License
Code is under the [Apache Licence v2](LICENCE).

