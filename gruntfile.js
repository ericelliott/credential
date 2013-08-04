'use strict';

module.exports = function(grunt) {

  grunt.initConfig({
    pkg: '<json:package.json>',
    jshint: {
      all: ['./*.js', './benchmarks/*.js', './test/*.js'],
      options: {
        curly: true,
        eqeqeq: true,
        immed: true,
        latedef: true,
        newcap: true,
        nonew: true,
        noarg: true,
        sub: true,
        undef: true,
        unused: true,
        eqnull: true,
        node: true,
        strict: true,
        boss: false
      }
    }
  });

  grunt.loadNpmTasks('grunt-contrib-jshint');

  grunt.registerTask('default', 'jshint');
  grunt.registerTask('test', 'jshint');
};
