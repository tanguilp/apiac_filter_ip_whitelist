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

  test "valid IPv6 address" do
    opts = APISexFilterIPWhitelist.init(whitelist: ["2001:F4E5:C0CA:4000::/50"])

    conn =
      conn(:get, "/")
      |> put_ip_address("2001:F4E5:C0CA:4049:D7:912E:FF00:0BD7")
      |> APISexFilterIPWhitelist.call(opts)

    refute conn.status == 403
    refute conn.halted
  end

  test "invalid IPv6 address" do
    opts = APISexFilterIPWhitelist.init(whitelist: ["2001:F4E5:C0CA:4000::/50"])

    conn =
      conn(:get, "/")
      |> put_ip_address("2001:F4E5:C0CA:E049:D7:912E:FF00:0BD7")
      |> APISexFilterIPWhitelist.call(opts)

    assert conn.status == 403
    assert conn.halted
  end

  test "subnet list with valid address" do
    whitelist = [
      "192.168.13.0/24",
      "2001:45B8:991A::/48",
      "23.12.0.0/16",
      "20E7:4128:D4F0:0::/64",
      "91.23.251.0/24"
    ]
    opts = APISexFilterIPWhitelist.init(whitelist: whitelist)

    conn =
      conn(:get, "/")
      |> put_ip_address("20E7:4128:D4F0:0::42")
      |> APISexFilterIPWhitelist.call(opts)

    refute conn.status == 403
    refute conn.halted
  end

  test "subnet list with invalid address" do
    whitelist = [
      "192.168.13.0/24",
      "2001:45B8:991A::/48",
      "23.12.0.0/16",
      "20E7:4128:D4F0:0::/64",
      "91.23.251.0/24"
    ]
    opts = APISexFilterIPWhitelist.init(whitelist: whitelist)

    conn =
      conn(:get, "/")
      |> put_ip_address("8.8.7.8")
      |> APISexFilterIPWhitelist.call(opts)

    assert conn.status == 403
    assert conn.halted
  end

  defp put_ip_address(conn, ip_address) do
    %{conn | remote_ip: InetCidr.parse_address!(ip_address)}
  end

  test "valid IPv4 address with fun callback" do
    opts = APISexFilterIPWhitelist.init(whitelist: &my_cidr_list/1)

    conn =
      conn(:get, "/")
      |> put_ip_address("23.91.178.41")
      |> APISexFilterIPWhitelist.call(opts)

    refute conn.status == 403
    refute conn.halted
  end

  defp my_cidr_list(_) do
    [
      "192.168.0.0/16",
      "23.91.178.32/28"
    ]
  end
end
