defmodule APIacFilterIPWhitelist do
  @behaviour Plug
  @behaviour APIac.Filter

  @moduledoc """
  An `APIac.Filter` plug enabling IP whitelist (IPv4 & IPv6)

  ## Plug options

  - `whitelist`: a *list* of allowed IPv4 and IPv6 addresses in CIDR notation or a
  `(Plug.Conn.t -> [String])` function returning that list of addresses
  - `exec_cond`: a `(Plug.Conn.t() -> boolean())` function that determines whether
  this filter is to be executed or not. Defaults to a function returning `true`
  - `send_error_response`: function called when IP address is not whitelisted.
  Defaults to `APIacFilterIPWhitelist.send_error_response/3`
  - `error_response_verbosity`: one of `:debug`, `:normal` or `:minimal`.
  Defaults to `:normal`

  ## Example

  ```elixir
  plug APIacFilterIPWhitelist, whitelist: [
    "192.168.13.0/24",
    "2001:45B8:991A::/48",
    "23.12.0.0/16",
    "20E7:4128:D4F0:0::/64",
    "91.23.251.0/24"
  ]
  ```

  ## Security considerations

  This plug uses the `remote_ip` field of the `Plug.Conn.t` for IP filtering, which means:
  - **do use** [`remote_ip`](https://github.com/ajvondrak/remote_ip) or a similar
  library if you're behind a proxy
  - **do not use** `remote_ip` or a similar library if you're not behind a proxy

  """

  @impl Plug
  def init(opts) do
    opts
    |> Enum.into(%{})
    |> Map.put(:whitelist, transform_whitelist(opts[:whitelist]))
    |> Map.put_new(:exec_cond, &__MODULE__.always_true/1)
    |> Map.put_new(:send_error_response, &__MODULE__.send_error_response/3)
    |> Map.put_new(:error_response_verbosity, :normal)
  end

  defp transform_whitelist(whitelist) when is_list(whitelist) do
    Enum.map(whitelist, fn cidr -> InetCidr.parse(cidr) end)
  end

  defp transform_whitelist(whitelist) when is_function(whitelist, 1), do: whitelist
  defp transform_whitelist(_), do: raise("Whitelist must be a list or a function")

  @impl Plug
  def call(conn, opts) do
    if opts[:exec_cond].(conn) do
      case filter(conn, opts) do
        {:ok, conn} ->
          conn

        {:error, conn, reason} ->
          opts[:send_error_response].(conn, reason, opts)
      end
    else
      conn
    end
  end

  @impl APIac.Filter
  def filter(conn, %{whitelist: whitelist}) do
    if do_filter(conn, whitelist) do
      {:ok, conn}
    else
      {:error, conn, %APIac.Filter.Forbidden{filter: __MODULE__, reason: :ip_not_whitelisted}}
    end
  end

  defp do_filter(conn, whitelist) when is_function(whitelist, 1) do
    do_filter(conn, whitelist.(conn))
  end

  defp do_filter(%Plug.Conn{remote_ip: remote_ip}, whitelist) do
    Enum.any?(
      whitelist,
      fn cidr -> InetCidr.contains?(cidr(cidr), remote_ip) end
    )
  end

  defp cidr(cidr) when is_binary(cidr), do: InetCidr.parse(cidr)
  defp cidr(cidr) when is_tuple(cidr), do: cidr

  @doc """
  Implementation of the `APIac.Filter` behaviour.

  ## Verbosity

  The following elements in the HTTP response are set depending on the value
  of the `:error_response_verbosity` option:

  | Error reponse verbosity | HTTP status             | Headers     | Body                                          |
  |:-----------------------:|-------------------------|-------------|-----------------------------------------------|
  | :debug                  | Forbidden (403)         |             | `APIac.Filter.Forbidden` exception's message |
  | :normal                 | Forbidden (403)         |             |                                               |
  | :minimal                | Forbidden (403)         |             |                                               |

  """
  @impl APIac.Filter
  def send_error_response(conn, %APIac.Filter.Forbidden{} = error, opts) do
    case opts[:error_response_verbosity] do
      :debug ->
        conn
        |> Plug.Conn.send_resp(:forbidden, Exception.message(error))
        |> Plug.Conn.halt()

      atom when atom in [:normal, :minimal] ->
        conn
        |> Plug.Conn.send_resp(:forbidden, "")
        |> Plug.Conn.halt()
    end
  end

  def always_true(_), do: true
end
