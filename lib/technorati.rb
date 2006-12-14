# {Technorati-Ruby}[http://pablotron.org/software/technorati-ruby/] - Technorati[http://technorati.com/] bindings for Ruby[http://ruby-lang.org/].
# by {Paul Duncan <pabs@pablotron.org>}[mailto:pabs@pablotron.org]
#
# For the latest version of this software, Please visit the 
# {Technorati-Ruby page}[http://pablotron.org/software/technorati-ruby/].
#
# Copyright (C) 2004-2006 {Paul Duncan}[http://pablotron.org/].
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies of the Software, its documentation and
# marketing & publicity materials, and acknowledgment shall be given
# in the documentation, materials and software packages that this
# Software was used.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#--
# :title: Technorati-Ruby API Documentation
#++
#

require 'parsedate'
require 'net/http'
require 'rexml/document'
require 'cgi'

#
# Ruby interface for the {Technorati API}[http://technorati.com/developers/].
#
# Note: In order to use this library you'll need an API key from the {Technorati developers page}[http://technorati.com/developers/].
#
# Using this class is straighforward; you create a new instance of this
# class with your API key, then query Technorati[http://technorati.com/]
# with the URL you want to learn about, like so:
#
#   # read API key from ~/.technorati_key
#   api_key_path = File.expand_path('~/.technorati_key')
#   api_key = File.read(api_key_path).strip
#
#   # create a new Technorati instance
#   tr = Technorati.new(api_key)
#
#   # fetch information about links to my page
#   cosmos = tr.cosmos('http://pablotron.org/')
# 
#   # print out the name and URL of the first link
#   puts %w{name link}.map { |key|
#     val = cosmos['items'][0][key]
#     "#{key}: #{val}"
#   }
# 
# Each of the query methods allows you to (optionally) refine your
# search by passing an hash of additional parameters as the second
# parameter.  For example, to limit the cosmos query above to 10 results
# of type 'weblog', you would write it like this:
#
#   # define cosmos query options
#   cosmos_opts = {
#     'limit' => 10,        # limit to 10 results
#     'type'  => 'weblog',  # results of type 'weblog'
#   }
#
#   # fetch information about links to my page
#   cosmos = tr.cosmos('http://pablotron.org/', cosmos_opts)
#   
# See the documentation for each method for additional information on
# the available options.
#   
class Technorati
  # Release version.
  VERSION = '0.2.0'

  # Technorati-specific error.
  class Error < StandardError; end

  # URL parsing error.
  class URLError < Error; end

  # HTTP connection error.
  class HTTPError < Error; end

  # An error returned from the \Technorati API.
  class APIError < Error; end


  # :stopdoc:

  TYPE_PROCS = {
    :str  => proc { |str| str },
    :int  => proc { |str| str.to_i },
    :time => proc { |str| Time.mktime(*ParseDate.parsedate(str)) },
    :flt  => proc { |str| str.to_f },
  }

  QUERY_SCHEMAS = {
    'cosmos'  => {
      'weblog/name'         => :str,
      'weblog/url'          => :str,
      'weblog/rssurl'       => :str,
      'weblog/atomurl'      => :str,
      'weblog/inboundblogs' => :int,
      'weblog/inboundlinks' => :int,
      'weblog/lastupdate'   => :time,
      'weblog/rank'         => :int,
      'nearestpermalink'    => :str,
      'excerpt'             => :str,
      'linkcreated'         => :time,
      'linkurl'             => :str,

      # author info (only set if claim=1)
      'weblog/author/username'          => :str,
      'weblog/author/firstname'         => :str,
      'weblog/author/lastname'          => :str,
      'weblog/author/thumbnailpicture'  => :str,

      # these are all <result>-specific
      'rankingstart'        => :int,
      'url'                 => :str,
    },

    'search'  => {
      'query'               => :str,
      'querycount'          => :int,
      'inboundblogs'        => :int,
      'querytime'           => :flt, # check this
      'rankingstart'        => :int,

      'weblog/name'         => :str,
      'weblog/url'          => :str,
      'weblog/rssurl'       => :str,
      'weblog/atomurl'      => :str,
      'weblog/inboundblogs' => :int,
      'weblog/inboundlinks' => :int,
      'weblog/lastupdate'   => :time,

      'title'               => :str,
      'excerpt'             => :str,
      'created'             => :time,
      'permalink'           => :str,

      # author info (only set if claim=1)
      'weblog/author/username'          => :str,
      'weblog/author/firstname'         => :str,
      'weblog/author/lastname'          => :str,
      'weblog/author/thumbnailpicture'  => :str,
    },

    'getinfo' => {
      'username'            => :str,
      'firstname'           => :str,
      'lastname'            => :str,
      'thumbnailpicture'    => :str,
      
      'weblog/name'         => :str,
      'weblog/url'          => :str,
      'weblog/rssurl'       => :str,
      'weblog/atomurl'      => :str,
      'weblog/inboundblogs' => :int,
      'weblog/inboundlinks' => :int,
      'weblog/lastupdate'   => :time,

      'rank'                => :int,
      'lang'                => :str,
      'lat'                 => :str,
      'lon'                 => :str,
      'foafurl'             => :str,
    },

    'tag'  => {
      'query'               => :str,
      'postsmatched'        => :int,
      'blogssmatched'       => :int,
      'start'               => :int,
      'limit'               => :int,
      'querytime'           => :flt,

      'weblog/name'         => :str,
      'weblog/url'          => :str,
      'weblog/rssurl'       => :str,
      'weblog/atomurl'      => :str,
      'weblog/inboundblogs' => :int,
      'weblog/inboundlinks' => :int,
      'weblog/lastupdate'   => :time,

      'title'               => :str,
      'excerpt'             => :str,
      'created'             => :time,
      'permalink'           => :str,
      'postupdate'          => :time,
    },

    'toptags' => {
      'limit'               => :int,

      'tag'                 => :str,
      'posts'               => :int,
    },

    'keyinfo' => {
      'apiqueries'          => :int,
      'maxqueries'          => :int,
    },

    'blogposttags' => {
      'tag'                 => :str,
      'posts'               => :int,
    },

    'bloginfo'  => {
      'url'                 => :str,
      'weblog/name'         => :str,
      'weblog/url'          => :str,
      'weblog/rssurl'       => :str,
      'weblog/atomurl'      => :str,
      'weblog/inboundblogs' => :int,
      'weblog/inboundlinks' => :int,
      'weblog/lastupdate'   => :time,
      'weblog/rank'         => :int,
      'weblog/lang'         => :str,
      'weblog/foafurl'      => :str,
      'inboundblogs'        => :int,
      'inboundlinks'        => :int,
    },
  }

  # :startdoc:

  # Default options for Technorati.new.
  DEFAULTS = {
    'api_url'     => 'http://api.technorati.com/',
    'user_agent'  => "Technorati-Ruby/#{Technorati::VERSION} Ruby/#{RUBY_VERSION}",
  }

  #
  # Connect to Technorati with key _key_
  #
  # Note: Will not raise an # exception until you make an actual call.  You can
  # get a key from the {Technorati developers page}[http://technorati.com/developers/].
  #
  # Example: 
  #   # read key from $HOME/.technorati_key
  #   api_key_path = File.expand_path('~/.technorati_key')
  #   api_key = File.read(key_path).strip
  #
  #   # use key to connect to technorati
  #   t = Technorati.new(api_key)
  #
  def initialize(key, opt = nil)
    @opt = DEFAULTS.merge(opt || {})
    @key = key
  end

  private

  # 
  # URI-escape a string.  This method is private.
  # 
  def u(str)
    CGI.escape(str)
  end

  # Environment variables to check for HTTP proxy
  PROXY_ENV_VARS = %w{TECHNORATI_HTTP_PROXY HTTP_PROXY http_proxy}

  #
  # Parse and verify a URL string.
  #
  def parse_url(url_str, name = 'URL')
    begin 
      uri = URI.parse(url_str)
    rescue Exception => e
      raise URLError, "couldn't parse #{name} '#{url_str}': #{e}"
    end

    # check URI scheme
    unless uri.scheme == 'http'
      raise URLError, "Unknown #{name} scheme: #{uri.scheme}"
    end

    # return URI
    uri
  end

  #
  # get the HTTP proxy server and port from the environment
  # Returns [nil, nil] if a proxy is not set
  #
  # This method is private
  #
  def find_http_proxy
    ret = [nil, nil]

    # check the platform.  If we're running in windows then we need to 
    # check the registry
    if @opt['use_proxy'] || @opt['proxy_url']
      if @opt['proxy_url'] && @opt['proxy_url'].size > 0
        uri = parse_url(@opt['proxy_url'], 'proxy URL')
        ret = [uri.host, uri.port]
      elsif RUBY_PLATFORM =~ /win32/i
        # Find a proxy in Windows by checking the registry.
        # this code shamelessly copied from Raggle :D

        require 'win32/registry'

        Win32::Registry::open(
          Win32::Registry::HKEY_CURRENT_USER,
          'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        ) do |reg|
          # check and see if proxy is enabled
          if reg.read('ProxyEnable')[1] != 0
            # get server, port, and no_proxy (overrides)
            server = reg.read('ProxyServer')[1]
            np = reg.read('ProxyOverride')[1]

            server =~ /^([^:]+):(.+)$/
            ret = [$1, $2]

            # don't bother with no_proxy support
            # ret['no_proxy'] = np.gsub(/;/, ',') if np && np.length > 0
          end
        end
      else
        # handle UNIX systems
        PROXY_ENV_VARS.each do |env_var|
          if ENV[env_var]
            # if we found a proxy, then parse it
            ret = ENV[env_var].sub(/^http:\/\/([^\/]+)\/?$/, '\1').split(':')
            ret[1] = ret[1].to_i if ret[1]
            break
          end
        end
        # $stderr.puts "DEBUG: http_proxy = #{ENV['http_proxy']}, ret = [#{ret.join(',')}]"
      end
    else 
      # proxy is disabled
      ret = [nil, nil]
    end

    # return host and port
    ret
  end

  #
  # Low-level HTTP GET.
  #
  # This method is private.
  #
  def http_get(url)
    # set HTTP version to 1.2
    Net::HTTP::version_1_2

    urls = %w{api proxy}.inject({}) do |ret, key|
      if url_val = @opt["#{key}_url"] 
        uri = parse_url(url_val, "#{key} URL")
        [:host, :port].each { |m| ret["#{key}_#{m}"] = uri.send(m) }
      end

      ret
    end

    # connect to technorati
    http = Net::HTTP.Proxy(urls['proxy_host'], urls['proxy_port']).new(urls['api_host'], urls['api_port'])
    http.start

    # $stderr.puts "DEBUG URL: #{url}"

    # create HTTP headers hash
    http_headers = {
      'User-Agent'  => @opt['user_agent']
    }

    # get URL, check for error
    resp = http.get(url, http_headers)
    raise Technorati::HTTPError, "HTTP #{resp.code}: #{resp.message}" unless resp.code =~ /2\d{2}/

    # close HTTP connection, return response
    http.finish
    resp.body
  end

  #
  # Get URL from Technorati, and optionally parse result and return as
  # an array of hashes as well.
  #
  # This method is private.
  #
  def get(schema, args = {}, method = nil)
  
    # convert arguments
    method ||= schema
    url = ("/#{method}?" << map_args(args))

    content = http_get(url)
    doc = REXML::Document.new(content)
    schema_keys = QUERY_SCHEMAS[schema].keys

    # if there was an error, raise an exception
    doc.root.elements.each('//error') do |e|
      raise APIError, "#{e.text}"
    end

    # grab toplevel result info
    result_elem = doc.root.elements['//document/result']
    ret = schema_keys.inject({}) do |elem_vals, key|
      if val = result_elem.elements[key]
        # out_key = key.gsub(/\//, '_')
        out_val = TYPE_PROCS[QUERY_SCHEMAS[schema][key]].call(val.text)
        elem_vals[key] = out_val
      end
      elem_vals
    end

    # grab each result item and toss it in the return array
    ret['items'] = []
    doc.root.elements.each('//document/item') do |e|
      # elements to grab from return XML
      ret['items'] << schema_keys.inject({}) do |elem_vals, key| 
        if val = e.elements[key]
          # out_key = key.gsub(/\//, '_')
          out_val = TYPE_PROCS[QUERY_SCHEMAS[schema][key]].call(val.text)
          elem_vals[key] = out_val
        end
        elem_vals
      end
    end

    # return results
    ret
  end

  #
  # Convert an arguments hash to a URL fragment
  #
  # This method is private.
  #
  def map_args(args) 
    args.merge({'key' => @key}).map { |ary|
      key, val = ary

      if val && %w{claim highlight}.include?(key)
        val = '1' 
      elsif key == 'current'
        val = val ? 'yes' : 'no'
      end
        
      "#{key}=#{u(val)}"
    }.join('&')
  end

  #
  # Convert a legacy cosmos call into a hash of options.
  #
  # This method is private.
  #
  def legacy_cosmos(args)
    warn "WARNING: Calling Technorati#cosmos this way is deprecated."
    warn "WARNING: Please update your code."

    keys = [
      ['limit',   :int],
      ['type',    :str],
      ['start',   :int],
      ['current', :bool],
    ]

    # map legacy cosmos call values to hash
    keys.zip(args).inject({}) do |ret, row|
      key, key_type, val = row.flatten

      if val.defined?
        case key_type
        when :int
          ret[key] = val.to_i
        when :str
          ret[key] = val
        when :bool
          ret[key] = (val.match(/^yes$/i) && true)
        else
          raise Error, "unknown key type #{key_type}"
        end
      end

      ret
    end
  end

  #
  # Convert a legacy search call into a hash of options.
  #
  # This method is private.
  #
  def legacy_search(args)
    warn "WARNING: Calling Technorati#search this way is deprecated."
    warn "WARNING: Please update your code."

    { 'start' => args } 
  end

  public

  # 
  # Get a list of sites linking to the given URL.  See 
  # http://technorati.com/developers/api/cosmos.html for additional
  # information.
  #
  # Note: This method has changed since 0.1.x. It takes a hash of
  # optional arguments as the second parameter.  Calling it with the old
  # 0.1-style parameters will work, but is deprecated, will print a
  # warning, and may stop working in a future release.
  #
  # Required Parameters:
  # * _url_: URL you are searching for. The 'http://' prefix is
  #   optional.
  # 
  # Any additional arguments are optional and may be passed as a hash.
  # Here's a description of each optional argument:
  #
  # Optional Arguments:
  # * _limit_: Set this to a number larger than 0 and smaller or equal to
  #   100 and it will return _limit_ number of links for a query. By
  #   default this value is 20.
  # * _type_: Set this to 'link' and you'll get the freshest links to your
  #   target URL. Set it to 'weblog' and you'll get a reverse blogroll -
  #   the last set of blogs that linked to the target URL.
  # * _start_: Set this to a number larger than 0 and you'll get the
  #   _start_ + _limit_ freshest items (links or blogs), e.g. set it to
  #   _limit_ + 1, and you'll get the second page of rankings.
  # * _current_: By default, cosmos returns the links that are currently
  #   on the source's index page. If you set _current_ to false, you
  #   will have all links to the given URL.
  # * _claim_: Set to true to include Technorati member data in the
  #   result set when a blog has been successfully claimed.  Defaults to
  #   false.
  #
  # Returns a hash containing information about the query URL and a 
  # list of blogs.
  #
  # Valid Return Keys:
  # * 'weblog/name': Name of blog.
  # * 'weblog/url':  URL of blog.
  # * 'weblog/rssurl': RSS syndication URL of blog.
  # * 'weblog/atomurl': Atom syndication URL of blog.
  # * 'weblog/inboundblogs': Number of inbound blogs.
  # * 'weblog/inboundlinks': Number of inbound links.
  # * 'weblog/lastupdate': Date of last update.
  # * 'nearestpermalink': Nearest permanent link.
  # * 'excerpt': Excerpt from page matching search result.
  # * 'linkcreated': Date link was created.
  # * 'linkurl': Link URL.
  # * 'weblog/rank': Cosmos Rank.
  # * rankingstart:
  # * 'url': URL.
  # * 'items': an array of hashes containing blogs
  #
  # Raises Technorati::Error on error.
  #
  # Examples:
  # 
  # Here's a basic cosmos query:
  #
  #   # basic cosmos query
  #   site = 'slashdot.org'
  #   puts tr.cosmos(site)['items'].map { |item| item['weblog/name'] }
  #  
  # And here's the same query with some options:
  #  
  #   # set query options
  #   site = 'slashdot.org'
  #   cosmos_opts = { 'limit' => 35 }
  #
  #   # run technorati cosmos query
  #   cosmos = tr.cosmos(site, cosmos_opts)
  #
  #   # print out a list of the first 35 sites linking to slashdot.org
  #   puts cosmos['items'].map { |item| item['weblog/name'] }
  #
  def cosmos(url, *args)
    args = (args.size > 0 && args[0].kind_of?(Hash)) ? legacy_cosmos(args) : {}
    args.update('url' => url)

    # execute query and return results
    get('cosmos', args)
  end

  #
  # Get a list of sites containing the given search string. See 
  # http://technorati.com/developers/api/search.html for additional
  # information.
  #
  # Note: This method has changed since 0.1.x. It takes a hash of
  # optional arguments as the second parameter.  Calling it with the old
  # 0.1-style parameters will work, but is deprecated, will print a
  # warning, and may stop working in a future release.
  #
  # Required Parameters: 
  # * _words_: an Array of words or a whitespace-delimited String
  # 
  # Any additional arguments are optional and may be passed as a hash.
  # Here's a description of each optional argument:
  #
  # Optional Arguments:
  # * _start_: Set this to a number larger than 0 and you'll get the
  #   _start_ + 20 freshest items (links or blogs), e.g. set it to 21,
  #   and you'll get the second page of rankings (21 through 40).
  # * _claim_: Set to true to include Technorati member data in the
  #   result set when a blog has been successfully claimed.  Defaults to
  #   false.
  # * _limit_: Set this to a number larger than 0 and smaller or equal to
  #   100 and it will return _limit_ number of links for a query. By
  #   default this value is 20.
  # * _language_: Set this to an {ISO 639-1}[http://www.loc.gov/standards/iso639-2/englangn.html] 
  #   language code to retrieve results specific to that language.
  #   According to the {Technorati API documetation}[http://technorati.com/developers/api/search.html],
  #   this feature is beta and may not work correctly.
  # * _authority_: Set this to filter results to those from blogs with
  #   at least the Technorati Authority specified. Technorati calculates a
  #   blog's authority by how many people link to it. Filtering by
  #   authority is a good way to refine your search results. There are
  #   four settings: 
  #
  #   * n:  Any authority: All results (default if unspecified).
  #   * a1: A little authority: Results from blogs with at least one link.
  #   * a4: Some authority: Results from blogs with a handful of links.
  #   * a7: A lot of authority: Results from blogs with hundreds of links.
  #
  # Returns a hash containing information about the query and a 
  # list of blogs.
  #
  # Valid Return Keys:
  # * 'query': Query string.  
  # * 'querycount': Number of matches.
  # * 'inboundblogs': Number of inbound blogs.
  # * 'querytime': Duration of query (in seconds).
  # * 'rankingstart': Value of start parameter.
  # * 'weblog/name': Name of blog containing match.
  # * 'weblog/url': URL of blog containing match.
  # * 'weblog/rssurl': RSS URL of blog containing match.
  # * 'weblog/atomurl': Atom URL of blog containing match.
  # * 'weblog/inboundblogs': Number of inbound blogs of blog containing match.
  # * 'weblog/inboundlinks': Number of inbound links of blog containing match.
  # * 'weblog/lastupdate': Date blog was last updated
  # * 'title': Title of matching entry.
  # * 'excerpt': Excerpt of matching entry with relevant text.
  # * 'created': Date matching entry was created.
  # * 'items': Array of hashes containing matching entries.
  #
  # Raises Technorati::Error on error.
  #
  # Examples:
  #   # basic search query
  #   tr.search('cooking')['items'].map { |item| item['weblog/url'] }
  #
  # Here's a more advanced search query:
  #
  #   # search query with options
  #   words = 'indian cooking'
  #   opts = { 
  #     'limit'     => 5,     # limit to first 5 results
  #     'authority' => 'a4',  # require a handful of links
  #   }
  #
  #   # execute query
  #   results = tr.search(words, opts)
  #
  #   # print results 
  #   puts results['items'].map { |item|
  #     { 'weblog/url' => 'Blog',
  #       'title'      => 'Title',
  #       'created'    => 'Date',
  #       'excerpt'    => 'Excerpt',
  #     }.map { |row| "#{row[1]}: #{item[row[0]]}" }
  #   }.flatten
  #
  def search(words, args = {})
    words = words.join(' ') if words.respond_to?(:join)

    # if this is an old-style call, then convert it.
    legacy_classes = [String, Numeric]
    args = legacy_search(args) if args && legacy_classes.any? { |c| args.kind_of?(c) }
    args.update('query' => words)

    # execute a search query and return the results
    get('search', args)
  end


  #
  # Get a list of posts with the given tag. See 
  # http://technorati.com/developers/api/tag.html for additional
  # information.
  #
  # Required Parameters: 
  # * _tag_: a String, such as 'blues' or 'xylophone'
  # 
  # Any additional arguments are optional and may be passed as a hash.
  # Here's a description of each optional argument:
  #
  # Optional Arguments:
  # * _start_: Set this to a number larger than 0 and you'll get the
  #   _start_ + 20 freshest posts, e.g. set it to 21, and you'll get the
  #   second page of posts (21 through 40).
  # * _limit_: Set this to a number larger than 0 and smaller or equal to
  #   100 and it will return _limit_ number of links for a query. By
  #   default this value is 20.
  # * _excerptsize_: Number of word characters to include in post
  #   excerpts.  Defaults to 100.
  # * _topexcerptsize_: Number of word characters to include in the
  #   first post excerpt.  Defaults to 150.
  #
  # Returns a hash containing information about the query URL and a 
  # list of blogs.
  #
  # Valid Return Keys:
  # * 'weblog/name': Name of blog.
  # * 'weblog/url':  URL of blog.
  # * 'weblog/rssurl': RSS syndication URL of blog.
  # * 'weblog/atomurl': Atom syndication URL of blog.
  # * 'weblog/inboundblogs': Number of inbound blogs.
  # * 'weblog/inboundlinks': Number of inbound links.
  # * 'weblog/lastupdate': Date of last update.
  # * 'excerpt': Excerpt from page matching search result.
  # * 'title': Title of matching post.
  # * 'excerpt': Excerpt of matching entry with relevant text.
  # * 'created': Date matching entry was created.
  # * 'permalink': Permanent link to this post.
  # * 'created': Date matching entry was last updated.
  # * 'items': an array of hashes containing matching posts
  #
  # Raises Technorati::Error on error.
  #
  # Examples:
  #   # search for posts matching 'banana' and print them out
  #   puts r.tag('banana')['items'].map { |post|
  #     "\"#{post['title']\" (#{post['permalink']}):\n=> #{post['excerpt']}"
  #   }
  #
  def tag(tag, args = {})
    args.update('tag' => tag)
    get('tag', args)
  end

  #
  # Get the top tags used on Technorati.  See
  # http://technorati.com/developers/api/toptags.html for additional
  # information.
  #
  # There are no required parameters for this method, however you may
  # pass a hash of optional arguments.  Here's a description of each
  # optional argument:
  #
  # Optional Arguments:
  # * _start_: Set this to a number larger than 0 and you'll get the
  #   _start_ + 20 highest-rated tags, e.g. set it to 21, and you'll get the
  #   second page of tags (21 through 40).
  # * _limit_: Set this to a number larger than 0 and smaller or equal to
  #   100 and it will return _limit_ number of tags. By default this
  #   value is 20.
  #
  # Valid Return Keys:
  # * 'limit': value of 'limit' parameter.
  # * 'items': Array of hashes containing matching tags.
  # * 'tag': Tag value.
  # * 'posts': Number of posts matching given tag.
  #
  # Example:
  #   # print out the top 20 tags on technorati
  #   puts tr.top_tags['items'].map { |tag| 
  #     "#{tag['tag']} (#{tag['posts']})"
  #   }
  # 
  def top_tags(args = {})
    get('toptags', args)
  end

  #
  # Get information about your key usage.  Note that calls to this
  # method do not count towards your limit.  See
  # http://technorati.com/developers/api/keyinfo.html for additional
  # information.
  #
  # Valid Return Keys:
  # * 'apiqueries': Number of queries today.
  # * 'maxqueries': Maximum number of allowed queries.
  #
  # Example:
  #   # print out the top 20 tags on technorati
  #   puts tr.top_tags['items'].map { |tag| 
  #     "#{tag['tag']} (#{tag['posts']})"
  #   }
  # 
  def key_info
    ret = get('keyinfo')
    ret.delete('items')
    ret
  end

  #
  # Get information that Technorati knows about a user.  See 
  # http://technorati.com/developers/api/getinfo.html for additional
  # information.
  #
  # In the simplest case you can use Technorati#info to find out information
  # that a blogger wants to make known about himself, along with some
  # information that Technorati has calculated and verified about that
  # person. The returned info is broken up into two sections: The first
  # part describes some information that the user wants to allow people
  # to know about him- or herself. The second part of the document is a
  # listing of the weblogs that the user has successfully claimed and
  # the information that Technorati knows about these weblogs.
  #
  # Parameters:
  # *  _user_ (required): Username
  #
  # Returns a hash containing information about the user and a 
  # list of blogs associated with that user.
  #
  # Valid Return Keys:
  # * 'username': User name of user.
  # * 'firstname': First name of user.
  # * 'lastname': Last name of user.
  # * 'thumbnailpicture': URL to thumbnail picture.
  # * 'weblog/name': Name of blog containing match.
  # * 'weblog/url: URL of blog containing match.
  # * 'weblog/rssurl': RSS URL of blog containing match.
  # * 'weblog/atomurl': Atom URL of blog containing match.
  # * 'weblog/inboundblogs': Number of inbound blogs of blog containing match.
  # * 'weblog/inboundlinks': Number of inbound links of blog containing match.
  # * 'weblog/lastupdate': Date blog was last updated.
  # * 'rank': Cosmos ranking.
  # * 'lang': Blog language as integer.
  # * 'lat': Geographical information.
  # * 'lon': Geographical information.
  # * 'foafurl': FOAF[http://foaf.org/] URL.
  # * 'items': an Array of Hashes with each matched user's blog.
  #
  # Raises Technorati::Error on error.
  #
  # Example:
  #   # print out a list of blog URLs associated with 'giblet'
  #   puts t.info('giblet')['items'] map { |blog| blog['weblog/url'] }
  #
  def info(user)
    args = { 'username' => user }
    get('getinfo', args)
  end

  #
  # Return information about the blog associated with a given URL.  See
  # http://technorati.com/developers/api/bloginfo.html for additional
  # information.
  # 
  # Note: This method has changed since 0.1.x. Version 0.1.0 had a
  # method named Technorati#bloginfo that accepted an optional second
  # parameter which was silently ignored.  The current version has been
  # renamed Technorati#blog_info , and does not accept a second
  # parameter.
  #
  # Parameters:
  # * _url_ (required): URL to search for ('http://' and 'www' prefix
  #   are optional).
  #
  # Returns a hash containing information about the query URL.
  #
  # Valid Return Keys:
  # * 'url': Blog URL.
  # * 'weblog/name': Name of blog.
  # * 'weblog/url: URL of blog.
  # * 'weblog/rssurl': RSS URL of blog.
  # * 'weblog/atomurl': Atom URL of blog.
  # * 'weblog/inboundblogs': Number of inbound blogs of blog.
  # * 'weblog/inboundlinks': Number of inbound links of blog.
  # * 'weblog/lastupdate': Date blog was last updated.
  # * 'weblog/rank': Blog cosmos rank.
  # * 'weblog/lang': Language of this blog.
  # * 'weblog/foafurl': FOAF (Friend of a Friend) URL for this blog.
  # * 'inboundblogs': Inbound blogs.
  # * 'inboundlinks': Inbound links. 
  #
  # Raises Technorati::Error on error.
  #
  # Example:
  #   # print out the Name, URL, and RSS URL for atrios.blogspot.com
  #   result = t.bloginfo('atrios.blogspot.com')
  #   blog_keys = { 'Name' => 'name', 'URL' =>'url', 'RSS' => 'rssurl' }
  #   puts blog_keys.map { |ary| "#{ary[0]}: #{result["weblog/#{ary[1]}"]}" }
  #   
  def blog_info(url)
    args = { 'url' => url }

    ret = get('bloginfo', args)
    ret.delete('items')
    ret
  end

  alias :bloginfo :blog_info

  #
  # Return top tags for posts on the given blog.  See
  # http://technorati.com/developers/api/blogposttags.html for additional
  # information.
  # 
  # Parameters:
  # * _url_ (required): URL to search for ('http://' and 'www' prefix
  #   are optional).
  #
  # Any additional arguments are optional and may be passed as a hash.
  # Here's a description of each optional argument:
  #
  # Optional Arguments:
  # * _limit_: Set this to a number larger than 0 and smaller or equal to
  #   100 and it will return _limit_ number of tags for the given blog. By
  #   default this value is 10.
  #
  # Returns a hash containing information about the query URL.
  #
  # Valid Return Keys:
  # * 'tag': Tag value.
  # * 'posts': Number of posts matching given tag.
  #
  # Raises Technorati::Error on error.
  #
  # Example:
  #   # print the top 10 tags for the site 'linuxbrit.co.uk':
  #   site = 'linuxbrit.co.uk'
  #   puts tr.blog_post_tags(site)['items'].map { |item|
  #     "#{item['tag']} (#{item['posts']})"
  #   }
  #
  def blog_post_tags(url, args = {})
    args = { 'url' => url }
    get('blogposttags', args)
  end
end
