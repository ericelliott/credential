# Credential

Fortify your user's passwords against rainbow table, brute force, and variable hash time attacks attacks using Node's built in crypto functions.

Employs cryptographically secure, per password salts to prevent rainbow table attacks.

Key stretching is used to make brute force attacks impractical.

## Installing

```
$ npm install --save credential
```

## Examples

### .hash()

```
var pw = require('credential'),
  newPassword = 'I have a really great password.';

pw.hash(newPassword, function (err, hash) {
  if (err) { throw err; }
  console.log('Store the password hash.', hash);
});
```

### .verify()

```
var pw = require('credential'),
  storedHash = 'o/HsuUsd1bjV2malqmakJDjwV7uPSHFtU4DS0ihsg3N9gzE210X1LJXT+dBUlO1DPjBckiWgwP680C89IKRxlQW0$pdkrKzyYRQLm07ZyU5T0wJS4FaxPQLg2j29XMF4ptY8hYH+eQ0XQDY89mdKFHBPZF5D6NDeynXqd2dhS7nDeaN7p',
  userInput = 'I have a really great password.';

pw.verify(storedHash, userInput, function (err, isValid) {
  var msg;
  if (err) { throw err; }
  msg = isValid ? 'Passwords match!' : 'Wrong password.';
  console.log(msg);
});
```

## API

### .hash()

`.hash(password, callback)`
`callback(err, hash) // 'salt$hash'`

Takes a new password and creates a unique salt and hash combination in the form `'salt$hash'`, suitable for storing in a single text field.

* @param {String} password  A password to hash encode.


### .verify()

`.verify(hash, input, callback)`
`callback(err, isValid)`

Takes a stored hash, password input from the user, and a callback, and determines whether or not the user's input matches the stored password.

* @param  {String}   hash     A stored password hash
* @param  {String}   input    User's password input
* @param  {Function} callback callback(err, isValid)


### .configure(options)

Alter defaults for `keylength` or `iterations`.

**Warning:** Decreasing these values can make your password
database less secure.

* @param  {Object} options
* @param  {Number} options.keylength
* @param  {Number} options.iterations
* @return {Object} credential  the credential object


## Motivation

Several other libraries claim to do the same thing, but fall short. Several fail to use cryptographically secure salts, which make salt guessing possible. Others fail to use either a long enough salt, or a long enough hash. The salt should be the same size of the hash. No shorter, and no longer.

Others fail to use key stretching, or fail to use enough iterations (taking into account processor speeds, and clustered attacks, while balancing that against user experience).

The hash should be sufficiently long not just to prevent an attack from a single machine, but to prevent an attack from a large cluster of machines.

## Background

Passwords should be stored with a one way encryption hash, so that even if a malicious intruder obtains access to the user database, they still won't have access to user passwords.

Passwords are vulnerable to the following common attacks:

* Rainbow tables
* Brute force
* Passwords stolen from third parties

### Rainbow tables

Rainbow tables are precomputed tables used to look up passwords using stolen hashes. Once bad guys get their hands on user passwords, they'll attempt to attack popular services such as email and bank accounts -- which spells very bad PR for your service.

There are rainbow tables that exist today which can discover every possible password up to 12 characters. To prevent password theft by rainbow table, users should choose passwords of at least 14 characters. Sadly, such passwords are definitely not convenient, particularly on mobile devices. In other words, you should not rely on users to select appropriate passwords.


#### Password Salts

One defence you can employ against rainbow tables is password salting. A salt is a sequence of random characters that gets paired with a password during the hashing process. Salts should be cryptographically secure random values of a length equal to the hash size. Salts are not secrets, and can be safely stored in plaintext alongside the user's other credentials.

Salting can protect passwords in a couple of ways.

First: A uniquely generated salt can protect your password databases against existing rainbow tables. Using a random salt makes your site immune from these attacks. However, if you use the same salt for every password, a new rainbow table can be generated to attack the password database.

Second: If two different users use the same password, the compromised password will grant access to both user accounts. To prevent that, you must use a unique salt for each password. Doing so makes a rainbow table attack impractical.


### Brute force

A brute force attack will attempt to crack a password by attempting a match using every possible character combination.

One way to thwart brute force attacks is to programatically lock a user's account after a handful of failed login attempts. However, that strategy won't protect passwords if an attacker gains access to the password database.

Key stretching can make brute force attacks impractical by increasing the time it takes to hash the password. This can be done by applying the hash function in a loop. The delay will be relatively unnoticed by a user trying to sign in, but will significantly hamper an attacker attempting to discover a password through brute force.


### Variable vs constant time equality

If it takes your service longer to say no to a slightly wrong password than a mostly wrong password, attackers can use that data to guess the password, similar to how you guess a word playing hangman. No, random time delays and network timing jitter don't help:

From Crosby et al. "Opportunities And Limits Of Remote Timing Attacks":

> We have shown that, even though the Internet induces significant timing jitter, we can reliably distinguish remote timing differences as low as 20µs. A LAN environment has lower timing jitter, allowing us to reliably distinguish remote timing differences as small as 100ns (possibly even smaller). These precise timing differences can be distinguished with only hundreds or possibly thousands of measurements.

The best way to beat these attacks is to use a constant time hash equality check, rather than an optimized check. That is easily achieved by iterating through the full hash before returning the answer, regardless of how soon the answer is known.

Read more from [Coda Hale's "A Lesson in Timing Attacks"](http://codahale.com/a-lesson-in-timing-attacks/).

*Created by Eric Elliott for the book, "Programming JavaScript Applications" (O'Reilly)*
