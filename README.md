# Please-open.it token leak extension 

**TL;DR** This is a chrome extension that checks oauth2/openid connect authentication process on any website. Just install it, log in and check for alerts and recommendations.

# Company

[Please-open.it](https://please-open.it) is a french company, specialized in authentication.
We deal with oauth2 especially with [keycloak](https://www.keycloak.org).

We have an offer based on "Keycloak as a service", get your own realm on our infrastructure.

We also built an authorization platform. It works with all common oauth2 providers (Google, Facebook, Twitter, Microsoft, ...) and adds : 
- user filtering based on email, Google Suite organization, groups membership on Facebook or any filtering on a user property
- Timebased authorizations
- Calendar restrictions

Works perfectly for doors, gates or any access control device with standard an industrial hardware.

## Intro

Several monthes ago, we discover data leak on pole emploi's website [2 failles de sécurité chez pole emploi - French](https://www.mathieupassenaud.fr/faille-pole-emploi/).
It shows severals and global problems : 
- lack of knowledge about authentication, oauth2 or openid connect standards (use of implicit flow)
- Webanalytics integrated without any control : [Web analytics are the worst auth enemy](https://www.mathieupassenaud.fr/webanalytics_enemy/)

For internal use, we have a small tool for authentication process analysis. This tool was based on [apache JMeter](http://jmeter.apache.org/) with proxy recording. 

We rebuilt this tool directly in Chrome using an extension. This extension checks only requests from a web page and checks for known patterns we already had. Then, a small output in an HTML popup shows potential problems.

In order to make your authentication more secure, this tool is now free and opensourced.

## Status of the project

It is a big draft for now, a stack of rules hardcoded in Javascript. It displays information about suspicious requests, or misuse of tokens.

Contributions are welcome.

## Installation

Today, the extension is not published on the Chrome Webstore. Google does manual review of it due to requested permissions.

Clone or download this repo.

Go to [chrome://extensions](chrome://extensions) and turn on "developer mode".
Click on "Load Unpacked"
Select the location where you cloned this repo.

[https://webkul.com/blog/how-to-install-the-unpacked-extension-in-chrome/](https://webkul.com/blog/how-to-install-the-unpacked-extension-in-chrome/)

The extension is now installed, you see a yellow lock near the address bar.

## How to use

Go to the authentication page of your website. The extensions is always listening.

![capture](https://github.com/please-openit/token-leak-extension/blob/master/images/capture.png)

It shows directly authentication steps with a message, a level an details.
- Green it is an info of a great use
- Gray means manual verification is required, for example a check on the http headers.
- Yellow a misuse
- Red a bad usage
- Red with a big border : a fix is required ASAP.

A "details" link reveals the context : initiator, HTTP Method and called URL.

"More ..." link gives you some recommendations from this repo.

Do not forget to clean all results between two tests.

Remember, it is a draft. Some cases are not well covered. IE, when an authorization_code is exchanged for an access_token using a backend (not with a direct call to authentication server), which is the best way to do, this exchange is sometimes not detected.
All informations from this app needs manual verifications.

## Recommendations

All recommendations are based on [Internet Engineering Task Force](https://ietf.org) and [oauth2](https://oauth.net/2/) standards. There are not obligations, and many ways to interpret.

Recommendations we write for this public tool are general, check for your frameworks, languages and usages to know how to implement the best standard for high security.

## Contribution

All contributions are welcome. Check wiki pages for recommendations.

background.js file is the analysis tool. A stack of "if" statements with string comparisons.
Local storage is needed to keep an environement between requests.

chrome.storage.local is the way we found to communicate results to popup html file.
