# Passport-Nylas

[Passport](http://passportjs.org) strategy for authenticating with [Nylas](https://nylas.com) using the OAuth 2.0 protocol API

This module lets you authenticate using Pocket in your Node.js applications.
By plugging into Passport. Twitter authentication can be easily and unobstusively integrated into any aplication or framework that supports [Express](http://expressjs.com).

## Installation

`npm install passport-nylas`


## Usage

#### Configure Strategy

The Nylas authentication strategy authenticates users using an email account from mail providers like `gmail`, `yahoo`, `outlook` and more.
The strategy requires a `verify` callback, which receives the access token and username as arguments. The `verify` callback must call `done` providing a user to complete authentication.

#### Authenticate Requests


