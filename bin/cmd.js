#!/usr/bin/env node
'use strict';

var program = require('commander');
var pluck = require('pluck-keys');
var credential = require('../credential');

var stdin = '';

program
  .command('hash [password]')
  .description('Hash password')
  .option('-w --work <work>', 'relative work load (0.5 for half the work)', Number)
  .option('-k --key-length <key-length>', 'length of salt', Number)
  .action(function (password, options){
    var pw = credential(pluck([
      'keyLength',
      'hashMethod',
      'work'
    ], options));

    pw.hash(stdin || password, function (err, result){
      if (err){
        return console.error(err);
      }

      console.log(result);
    });
  });

program
  .command('verify [hash] <password>')
  .description('Verify password')
  .action(function (hash, password){
    credential().verify(stdin || hash, password, function (err, valid){
      if (err){
        return console.error(err);
      }

      if (!valid){
        throw new Error('Invalid');
      }

      console.log('Verified');
    });
  });

if (process.stdin.isTTY) {
  program.parse(process.argv);
} else {
  process.stdin.on('readable', function (){
    stdin += this.read() || '';
  });

  process.stdin.on('end', function (){
    program.parse(process.argv);
  });
}
