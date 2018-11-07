defmodule APISexFilterIPWhitelistTest do
  use ExUnit.Case
  use Plug.Test
  doctest APISexFilterIPWhitelist

  test "valid IPv4 address" do
    opts = APISexFilterIPWhitelist.init(whitelist: ["221.92.0.0/16"])

    conn =
      conn(:get, "/")
      |> put_ip_address("221.92.173.24")
      |> APISexFilterIPWhitelist.call(opts)

    refute conn.status == 403
    refute conn.halted
  end

  test "invalid IPv4 address" do
    opts = APISexFilterIPWhitelist.init(whitelist: ["221.92.0.0/16"])

    conn =
      conn(:get, "/")
      |> put_ip_address("17.195.73.12")
      |> APISexFilterIPWhitelist.call(opts)

    assert conn.status == 403
    assert conn.halted
  end

  defp put_ip_address(conn, ip_address) do
    %{conn | remote_ip: InetCidr.parse_address!(ip_address)}
  end
end
