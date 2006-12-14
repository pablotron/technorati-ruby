
# load libraries

require 'rake/rdoctask'
require 'rake/packagetask'
require 'rake/gempackagetask'

require 'lib/technorati.rb'

def package_info
  require 'ostruct'
  require 'rubygems'

  # create package
  ret = OpenStruct.new

  # set package information
  ret.name          = 'Technorati-Ruby'
  ret.blurb         = 'Technorati (http://technorati.com/) bindings for Ruby.'
  ret.version       = Technorati::VERSION
  ret.platform      = Gem::Platform::RUBY
  ret.url           = 'http://pablotron.org/software/technorati-ruby/'

  # author information
  ret.author_name   = 'Paul Duncan'
  ret.author_email  = 'pabs@pablotron.org'

  # requirements and files
  ret.reqs          = ['none']
  ret.include_files = Dir['**/*'].delete_if { |path| 
    %w{CVS .svn .hg}.any? { |chunk| path.include?(chunk) }
  }
      
  # rdoc info
  ret.rdoc_title    = "#{ret.name} #{ret.version} API Documentation"
  ret.rdoc_options  = %w{--webcvs http://hg.pablotron.org/technorati-ruby}
  ret.rdoc_dir      = 'doc'
  ret.rdoc_files    = %w{lib/**/*.rb README ChangeLog COPYING examples/**/*}

  # runtime info
  ret.auto_require  = 'technorati'
  ret.require_path  = 'lib'
  ret.package_name  = 'technorati-ruby'

  # package signing
  if ENV['GEM_SIGNING_KEY'] && ENV['GEM_SIGNING_CHAIN']
    ret.signing_key = File.expand_path(ENV['GEM_SIGNING_KEY'])
    ret.signing_chain = ENV['GEM_SIGNING_CHAIN'].split(',').map { |path|
      File.expand_path(path)
    }
  end

  # package release dir
  if path = ENV['RAKE_PACKAGE_DIR']
    ret.pkg_dir = File.join(File.expand_path(path), ret.package_name)
  end

  # return package
  ret
end

pkg = package_info

gem_spec = Gem::Specification.new do |s|
  # package information
  s.name = pkg.name.downcase
  s.platform = pkg.platform
  s.version = pkg.version
  s.summary = s.description = pkg.blurb

  # files
  pkg.reqs.each { |req| s.requirements << req }
  s.files = pkg.include_files

  # runtime info
  s.require_path = pkg.require_path
  s.autorequire = pkg.auto_require

  # rdoc info
  s.has_rdoc = true
  s.rdoc_options = ['--title', pkg.rdoc_title] + pkg.rdoc_options + pkg.rdoc_files

  # author and project details
  s.author = pkg.author_name
  s.email = pkg.author_email
  s.homepage = pkg.url

  # gem crypto stuff
  if pkg.signing_key && pkg.signing_chain
    s.signing_key = pkg.signing_key
    s.cert_chain = pkg.signing_chain
  end
end

Rake::GemPackageTask.new(gem_spec) do |p|
  p.need_tar_gz = true
  p.need_pgp_signature = true
  p.package_dir = pkg.pkg_dir if pkg.pkg_dir
end


Rake::RDocTask.new do |rd|
  rd.title = pkg.rdoc_title
  rd.rdoc_dir = pkg.rdoc_dir
  rd.rdoc_files.include(pkg.rdoc_files)
  rd.options.concat(pkg.rdoc_options)
end

task :clean => [:clobber]
task :release => [:clean, :package]
