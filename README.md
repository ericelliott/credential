# Credential

Easy password hashing and verification in Node. Protects against brute force, rainbow tables, and timing attacks.

Employs cryptographically secure, per password salts to prevent rainbow table attacks. Key stretching is used to make brute force attacks impractical. A constant time verification check prevents variable response time attacks.

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
  storedHash = '{"hash":"PJM0MHOz+qARffD4kJngkBlzGeR1U5ThUMx3aPW+qVokea7t5UhKXU8z8CTHTaf3MYLpnt/8dtdaCf7GxMUXr0cJ","salt":"oLfUniVJ9YcpNGzpAi8AQxzGzVBzC26AgsnmjNlEXWR6XGWl+08b+b5Px7jSebErDjkEuoovqkMpnk9D52gkA1M0","keyLength":66,"hashMethod":"pbkdf2","workUnits":60}',
  userInput = 'I have a really great password.';

pw.verify(storedHash, userInput, function (err, isValid) {
  var msg;
  if (err) { throw err; }
  msg = isValid ? 'Passwords match!' : 'Wrong password.';
  console.log(msg);
});
```

## API

### .hash(password, callback) callback(err, hashJSON)

Takes a new password and creates a unique hash. Passes a JSON encoded object to the callback.

* @param  {[type]}   password
* @param  {Function} callback


#### callback(err, hashJSON)

* @param  {Error}   Error     Error or null
* @param  {JSON} hashObject
* @param  {String} hashObject.hash
* @param  {String} hashObject.salt
* @param  {Number} hashObject.keyLength Bytes in hash
* @param  {String} hashObject.hashMethod
* @param  {Number} hashObject.workUnits


### .verify(hash, input, callback) callback(err, isValid)

Takes a stored hash, password input from the user, and a callback, and determines whether or not the user's input matches the stored password.

* @param  {String}   hash     A stored password hash
* @param  {String}   input    User's password input
* @param  {Function} callback(err, isValid)


### .configure(options)

Alter settings or set your secret `workKey`. The  `workKey` is a secret value between one and 999, required to verify passwords. This secret makes it harder to brute force passwords from a stolen database by obscuring the number of iterations required to test passwords.

Warning: Decreasing `keyLength` or `workUnits` can make your password database less secure.

* @param  {Object} options Options object.
* @param  {Number} options.keyLength
* @param  {Number} options.workUnits
* @param  {Number} options.workKey secret
* @return {Object} credential object


## Motivation

Several other libraries claim to do the same thing, but fall short. Several fail to use cryptographically secure salts, which make salt guessing possible. Others fail to use either a long enough salt, or a long enough hash. The salt should be the same size as the hash. No shorter, and no longer.

Others fail to use key stretching, or fail to use enough iterations (taking into account processor speeds, and clustered attacks, while balancing that against user experience).


## Background

Passwords should be stored with a one way encryption hash, so that even if a malicious intruder obtains access to the user database, they still won't have access to user passwords.

The hash should be sufficiently long not just to prevent an attack from a single machine, but to prevent an attack from a large cluster of machines.

Worms targeting vulnerable versions of popular website platforms such as WordPress and Drupal have become common. Once such a worm takes control of a website and installs its payload, it can recruit all of the site's traffic into a JavaScript botnet, and, among other things, use visitor CPU power to crack stolen password databases which fail to implement the security precautions outlined here.

There are botnets that exist today with [over 90,000 nodes](http://www.forbes.com/sites/anthonykosner/2013/04/13/wordpress-under-attack-how-to-avoid-the-coming-botnet/). Such botnets could crack MD5 password hashes at a rate of nine billion per second.

Passwords are vulnerable to the following common attacks:

* Rainbow tables
* Brute force
* Passwords stolen from third parties

### Rainbow tables

Rainbow tables are precomputed tables used to look up passwords using stolen hashes. Once bad guys get their hands on user passwords, they'll attempt to attack popular services such as email and bank accounts -- which spells very bad PR for your service.

There are [rainbow tables that exist today](http://www.codinghorror.com/blog/2007/09/rainbow-hash-cracking.html) which can discover almost every possible password up to 14 characters. To prevent password theft by rainbow table, users should choose [passwords of at least 14 characters](http://en.wikipedia.org/wiki/Rainbow_table). Sadly, such passwords are definitely not convenient, particularly on mobile devices. In other words, you should not rely on users to select appropriate passwords.

Rainbow tables can significantly reduce the time it takes to find a password, at the cost of memory, but with terrabyte hard drives and gigabytes of RAM, it's a trade off that is easily made.


#### Password Salts

One defence you can employ against rainbow tables is password salting. A salt is a sequence of random characters that gets paired with a password during the hashing process. Salts should be cryptographically secure random values of a length equal to the hash size. Salts are not secrets, and can be safely stored in plaintext alongside the user's other credentials.

Salting can protect passwords in a couple of ways.

First: A uniquely generated salt can protect your password databases against existing rainbow tables. Using a random salt makes your site immune from these attacks. However, if you use the same salt for every password, a new rainbow table can be generated to attack the password database.

Second: If two different users use the same password, the compromised password will grant access to both user accounts. To prevent that, you must use a unique salt for each password. Doing so makes a rainbow table attack impractical.


### Brute force

Rainbow tables get all the blogger attention, but Moore's Law is alive and well, and brute force has become a very real threat. Attackers are employing GPUs, super computing clusters that cost less than $2,000, and JavaScript botnets comprised of tens of thousands of browsers visiting infected websites.

A brute force attack will attempt to crack a password by attempting a match using every possible character combination. A simple single-iteration hash can be tested at the rate of millions of hashes per second on modern systems.

One way to thwart brute force attacks is to programatically lock a user's account after a handful of failed login attempts. However, that strategy won't protect passwords if an attacker gains access to the password database.

Key stretching can make brute force attacks impractical by increasing the time it takes to hash the password. This can be done by applying the hash function in a loop. The delay will be relatively unnoticed by a user trying to sign in, but will significantly hamper an attacker attempting to discover a password through brute force.

For example, I discovered 100 hashes in less than 1ms using a simple MD5 algorithm, and then tried the same thing with Node's built-in `crypto.pbkdf2()` function (HMAC-SHA1) set to 80,000 iterations. PBKDF2 took 15.48 seconds. To a user performing a single login attempt per response, the slow down is barely noticed, but it slows brute force to a crawl.


### Variable vs constant time equality

If it takes your service longer to say no to a slightly wrong password than a mostly wrong password, attackers can use that data to guess the password, similar to how you guess a word playing hangman. You might think that random time delays and network timing jitter would sufficiently mask those timing differences, but it turns out an attacker just needs to take more timing samples to filter out the noise and obtain statistically relevant timing data:

From Crosby et al. "Opportunities And Limits Of Remote Timing Attacks":

> We have shown that, even though the Internet induces significant timing jitter, we can reliably distinguish remote timing differences as low as 20µs. A LAN environment has lower timing jitter, allowing us to reliably distinguish remote timing differences as small as 100ns (possibly even smaller). These precise timing differences can be distinguished with only hundreds or possibly thousands of measurements.

The best way to beat these attacks is to use a constant time hash equality check, rather than an optimized check. That is easily achieved by iterating through the full hash before returning the answer, regardless of how soon the answer is known.

Read more from [Coda Hale's "A Lesson in Timing Attacks"](http://codahale.com/a-lesson-in-timing-attacks/).

*Created by Eric Elliott for the book, ["Programming JavaScript Applications" (O'Reilly)](http://ericleads.com/javascript-applications/)*
