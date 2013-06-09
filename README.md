# Credential

Fortify your user's passwords against rainbow table and brute force attacks using Node's built in crypto functions.

Employs cryptographically secure, password unique salts to prevent rainbow table attacks.

Key stretching is used to make brute force attacks impractical.

Several other libraries claim to do the same thing, but fall short. Several fail to use cryptographically secure salts, which make salt guessing possible. Others fail to use either a long enough salt, or a long enough hash. The salt should be the same size of the hash. No shorter, and no longer.

Others fail to use key stretching, or fail to use enough iterations (taking into account processor speeds, and clustered attacks, while balancing that against user experience).

The hash should be sufficiently long not just to prevent an attack from a single machine, but to prevent an attack from a large cluster of machines.


## Motivation

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

*Created by Eric Elliott for the book, "Programming JavaScript Applications" (O'Reilly)*
