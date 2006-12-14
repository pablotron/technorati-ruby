#!/usr/bin/env ruby

#######################################################################
# referrer.rb - build a RSS feed of site referrers                    #
# by Paul Duncan <pabs@pablotron.org>                                 #
#######################################################################

# load technorati bindings
require 'cgi'
require 'time'
require 'erb'
require 'technorati'

class Technorati
  #
  # Simple example class that builds a RSS feed of blog posts referring
  # to the given blog.
  # 
  class Referrer
    #
    # Create a new Referrer and run it with the specified arguments.
    # Used to run this class from the command-line.
    #
    def self.run(args)
      url = args.shift || 'pablotron.org'
      key = Technorati.load_key
      puts Referrer.new(key).run(url)
    end

    #
    # Create a new Referrer instance with the specified API key.
    #
    def initialize(key)
      @tr = Technorati.new(key)
      @tmpl = {
        :rss  => ERB.new(RSS_TMPL),
        :item => ERB.new(ITEM_TMPL),
      }
    end

    #
    # Run Referrer on specified URL and return the result as string of
    # RSS contents.
    #
    def run(url)
      result = @tr.cosmos(url)
      @tmpl[:rss].result(binding)
    end

    private

    #
    # HTML-escape the specified string.
    #
    # This method is private.
    #
    def h(str)
      CGI.escapeHTML(str)
    end

    #
    # URL-escape the specified string.
    #
    # This method is private.
    #
    def u(str)
      CGI.escape(str)
    end

    #
    # run RSS item template on given url/item.
    #
    # This method is private.
    #
    def rss_item(url, item)
      @tmpl[:item].result(binding)
    end

    # ERuby template for RSS feed.
    RSS_TMPL = <<-END_RSS_TMPL
<?xml version='1.0' encoding='utf-8'?>
<rss version='2.0'>
  <channel>
    <title>Technorati: Sites Linking to <%= h(url) %></title>
    <link>http://technorati.com/</link>
    <description>
      A list of sites linking to <%= h(url) %> according to 
      &lt;a href='http://technorati.com/'&gt;Technorati&lt;/a&gt;.
    </description>

    <%= result.items.map { |item| rss_item(url, item) }.join %>
  </channel>
</rss>
END_RSS_TMPL

    # ERuby template for RSS items.
    ITEM_TMPL = <<-END_ITEM_TMPL
  <item>
    <title><%= h(item.weblog_name) %></title>
    <link><%= h(item.weblog_url) %></link>
    <pubDate><%= h(item.linkcreated.httpdate) %></pubDate>
    <description>
      This site links to <%= h(url) %>. 
      <%= h(item.excerpt ? 'Exerpt:' << item.excerpt : '') %>
    </description>
  </item>
END_ITEM_TMPL
  end
end

Technorati::Referrer.run(ARGV) if __FILE__ == $0
