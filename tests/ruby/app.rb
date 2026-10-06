require 'open3'
require 'shellwords'
require_relative 'helper'

class Runner
  def initialize(cmd)
    @cmd = cmd
  end

  def run
    system(@cmd)
  end
end

def direct
  name = gets
  system("ls " + name)
end

def through_helper
  value = params[:file]
  File.read(value)
end

def safe
  name = gets
  system("ls " + Shellwords.escape(name))
end

def stored
  r = Runner.new(gets)
  r.run
end

def branches(flag)
  x = ARGV[0]
  if flag
    y = x
  else
    y = "fixed"
  end
  eval(y)
end

def blocks
  items = [gets, "b"]
  items.each { |i| Open3.capture2(i) }
end

def rescued
  begin
    data = Marshal.load(gets)
  rescue StandardError => e
    puts e
  ensure
    puts "done"
  end
end

def implicit_return(x) = x

def modifier(n)
  return unless n
  exec(n) if n == "a"
end
