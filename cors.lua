require 'apache2'

-- CORSを許可したいOriginホスト名を列挙します, サブドメインも許可されます, "*"が指定された場合全てのOriginを許可します
AllowOrigins = { "example.com", "example.jp" }
-- localhost, .local, プライベートIP などのローカルなOriginを許可します
AllowPrivateOrigins = true
-- GET,POST,HEAD以外のメソッドを利用する場合はtrueにします
AllowRequestMethod = true
-- 追加のリクエストヘッダを利用する場合はtrueにします
AllowRequestHeaders = true
-- CookieまたはAuthorizationヘッダを利用する場合はtrueにします
AllowCredentials = false
-- 追加で利用可能にしたいレスポンスヘッダを列挙します
ExposeHeaders = {}
-- preflightリクエストの結果をクライアントキャッシュ可能なら時間を秒で指定します
AccessControlMaxAge = 3600

function add_cors(r)
  if not r.is_initial_req then
    return nil
  end
  local allowOrigin = getAllowOrigin(r)
  if allowOrigin then
    r.headers_out["Access-Control-Allow-Origin"] = allowOrigin
    -- Access-Control-Allow-Origin 以外はpreflightリクエストのレスポンス時のみ出力すればよい
    if r.method == "OPTIONS" then
      if AllowRequestMethod then
        local allowMethods = getAllowMethods(r)
        if allowMethods then
          r.headers_out["Access-Control-Allow-Methods"] = allowMethods
        end
      end
      if AllowRequestHeaders then
        local allowHeaders = getAllowHeaders(r)
        if allowHeaders then
          r.headers_out["Access-Control-Allow-Headers"] = allowHeaders
        end
      end
      if AllowCredentials then
        r.headers_out["Access-Control-Allow-Credentials"] = "true"
      end
      if ExposeHeaders and 0 < table.getn(ExposeHeaders) then
        r.headers_out["Access-Control-Expose-Headers"] = table.concat(ExposeHeaders, ", ")
      end
      if AccessControlMaxAge and 0 < AccessControlMaxAge then
        r.headers_out["Access-Control-Max-Age"] = AccessControlMaxAge
      end
    end
  end
  return apache2.DECLINED
end

function getAllowHeaders(r)
  local requestHeaders = r.headers_in["Access-Control-Request-Headers"]
  if requestHeaders and r:regex(requestHeaders, "^[a-zA-Z0-9-]+(?=, ?[a-zA-Z0-9-]+)*") then
    return requestHeaders
  end
  return nil
end

function getAllowMethods(r)
  local requestMethod = r.headers_in["Access-Control-Request-Method"]
  -- 仕様上はGET,HEAD,POSTは常に許可されるので含める必要がない筈だし、んだがバグったクライアントが居るらしいので列挙、OPTIONSも要バグクライアント対応で入れといたほうが良いらしい
  if requestMethod and requestMethod ~= "GET" and requestMethod ~= "POST" and requestMethod ~= "HEAD" and requestMethod ~= "OPTIONS" and requestMethod:find("^[A-Z]+$") then
    return "GET, POST, HEAD, OPTIONS, " .. requestMethod
  end
  return nil
end

function getAllowOrigin(r)
  local origin = r.headers_in["Origin"]
  if origin then
    local m = r:regex(origin, "^(https?)://([a-zA-Z0-9%.-]+)(?=:([0-9]+))?")
    if m then
      local origin_scheme = m[1]
      local origin_host = m[2]
      local origin_port = m[3]
      if r:regex(origin_host, getAllowOriginHostPattern()) then
        return origin
      end
      if AllowPrivateOrigins then
        if r:regex(origin_host, "^(localhost|.*\\.local|((10|127)\\.\\d+|192\\.168|172\\.(1[6-9]|2\\d|3[01]))\\.\\d+\\.\\d+)$") then
          return origin
        end
      end
    end
  end
  return nil
end

function getAllowOriginHostPattern()
  if not getAllowOriginHostPattern_cache then
    local i, v, p
    p = "^(.+\\.)?("
    for i,v in ipairs(AllowOrigins) do
      if v == "*" then
        getAllowOriginHostPattern_cache = "."
        return getAllowOriginHostPattern_cache
      end
      if i ~= 0 then
        p = p .. "|"
      end
      p = p .. v:gsub("%.", "\\.")
    end
    p = p .. ")$"
    getAllowOriginHostPattern_cache = p
  end
  return getAllowOriginHostPattern_cache
end
