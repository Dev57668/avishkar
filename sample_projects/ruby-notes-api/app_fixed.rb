require 'sinatra'
require 'sqlite3'
require 'bcrypt'
require 'json'
require 'openssl'
require 'securerandom'
require 'shellwords'

# Secure Ruby API — demonstrating the fixes
DB = SQLite3::Database.new(':memory:')
DB.execute('CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT, owner TEXT)')
DB.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, pw_hash TEXT)')

# Secrets loaded from environment
ADMIN_SECRET = ENV.fetch('ADMIN_SECRET')
API_KEY      = ENV.fetch('API_KEY')

get '/notes' do
  content_type :json
  owner = params[:owner]
  # Parameterised query — owner is a bound argument
  rows = DB.execute('SELECT id, title FROM notes WHERE owner = ?', owner)
  rows.to_json
end

post '/search' do
  content_type :json
  term = params[:q]
  rows = DB.execute('SELECT id, title FROM notes WHERE title LIKE ?', "%#{term}%")
  rows.to_json
end

get '/export' do
  name = params[:name]
  base = '/srv/notes'
  safe = File.expand_path(name, base)
  halt 400 unless safe.start_with?(base + '/')
  File.read(safe)
end

post '/run' do
  dir = Shellwords.escape(params[:cmd].to_s)
  output = `ls -la #{dir}`
  output
end

post '/login' do
  pw = params[:password]
  # bcrypt for password storage
  user = DB.execute('SELECT id, pw_hash FROM users WHERE name = ?', params[:name]).first
  halt 401 unless user && BCrypt::Password.new(user[1]) == pw
  { ok: true }.to_json
end

get '/token' do
  token = SecureRandom.urlsafe_base64(32)
  { token: token }.to_json
end

get '/reflect' do
  name = Rack::Utils.escape_html(params[:name].to_s)
  "<h1>Hello #{name}</h1>"
end

configure do
  # TLS verification on (default)
end
