defmodule APISexFilterIPWhitelist do
  @behaviour Plug
  @behaviour APISex.Filter

  @moduledoc """
  Documentation for APISexFilterIPWhitelist.

  - `set_filter_error_response`: if `true`, sets the HTTP status code to `403`.
  If false, does not do anything. Defaults to `true`
  - `halt_on_filter_failure`: if set to `true`, halts the connection and directly sends the
  response. When set to `false`, does nothing and therefore allows dealing with the error
  later in the code. Defaults to `true`
  """

  @impl Plug
  def init(opts) do
    unless is_list(opts[:whitelist]), do: raise "Missing whitelist parameter"

    opts
    |> Enum.into(%{})
    |> Map.put_new(:set_filter_error_response, true)
    |> Map.put_new(:halt_on_filter_failure, true)
  end

  @impl Plug
  def call(conn, opts) do
    case filter(conn, opts) do
      {:ok, conn} ->
        conn

      {:error, conn, reason} ->
        conn =
          if opts[:set_filter_error_response] do
            set_error_response(conn, reason, opts)
          else
            conn
          end

        if opts[:halt_on_filter_failure] do
          conn
          |> Plug.Conn.send_resp()
          |> Plug.Conn.halt()
        else
          conn
        end
    end
  end

  @impl APISex.Filter
  def filter(conn, opts) do
    %Plug.Conn{remote_ip: remote_ip} = conn

    if Enum.any?(opts[:whitelist],
                 fn cidr -> InetCidr.contains?(InetCidr.parse(cidr), remote_ip) end) do
      {:ok, conn}
    else
      {:error, conn, %APISex.Filter.Forbidden{filter: __MODULE__, reason: :ip_not_whitelisted}}
    end
  end

  @impl APISex.Filter
  def set_error_response(conn, %APISex.Filter.Forbidden{}, _opts) do
    conn
    |> Plug.Conn.resp(:forbidden, "")
  end
end
