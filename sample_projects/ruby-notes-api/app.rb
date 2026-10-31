require 'sinatra'
require 'sqlite3'
require 'digest'
require 'json'
require 'openssl'

# Intentionally insecure Ruby API — for education only
DB = SQLite3::Database.new(':memory:')
DB.execute('CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT, owner TEXT)')
DB.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, pw_hash TEXT)')

# Hard-coded admin token — anyone who reads this code has the token
ADMIN_SECRET = "ruby-admin-token-9f2c3d1a"
API_KEY = "sk-ruby-plaintext-api-key-8b4e7d2a"

get '/notes' do
  content_type :json
  owner = params[:owner]
  # SQL built by string interpolation — owner is unsanitised request data
  rows = DB.execute("SELECT id, title FROM notes WHERE owner = '#{owner}'")
  rows.to_json
end

post '/search' do
  content_type :json
  term = params[:q]
  # Another SQL injection via interpolation
  rows = DB.execute("SELECT id, title FROM notes WHERE title LIKE '%#{term}%'")
  rows.to_json
end

get '/export' do
  name = params[:name]
  # Path traversal: File.read with unsanitised request data
  content = File.read("/srv/notes/#{name}")
  content
end

post '/run' do
  cmd = params[:cmd]
  # Command injection via system with interpolated string
  output = `ls -la #{cmd}`
  output
end

post '/login' do
  pw = params[:password]
  # Weak hash: MD5 for password verification
  hash = Digest::MD5.hexdigest(pw)
  user = DB.execute("SELECT id FROM users WHERE pw_hash = '#{hash}'").first
  user ? { ok: true }.to_json : halt(401)
end

get '/token' do
  # Weak random: rand() for a security token
  token = rand(10_000_000).to_s
  { token: token }.to_json
end

get '/reflect' do
  name = params[:name]
  # XSS: request data written to response unescaped
  "<h1>Hello #{name}</h1>"
end

configure do
  # TLS verification disabled for outbound requests
  http_options = { ssl_verify_mode: OpenSSL::SSL::VERIFY_NONE }
end
