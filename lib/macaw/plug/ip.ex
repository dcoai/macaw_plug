defmodule Macaw.Plug.Ip do
  @moduledoc """
  IP addresses and CIDR blocks: parsing, membership and normalization.

  An IPv4 address that arrives in IPv4-mapped IPv6 form (`::ffff:203.0.113.5`,
  as a dual-stack listener can report its peer) is normalized to its IPv4
  form, so a trusted IPv4 proxy matches however the socket reported it.
  """

  import Bitwise

  @type ip :: :inet.ip_address()
  @type cidr :: {ip(), 0..128}

  @doc "Parses an address string to a normalized tuple, or returns nil."
  @spec parse(String.t()) :: ip() | nil
  def parse(text) when is_binary(text) do
    case :inet.parse_strict_address(String.to_charlist(String.trim(text))) do
      {:ok, ip} -> normalize(ip)
      {:error, _} -> nil
    end
  end

  @doc """
  Parses a CIDR (`"10.0.0.0/8"`, `"2001:db8::/32"`) or a single address
  (`"192.0.2.1"`, a /32 or /128) to `{network, prefix}`, or returns an error
  naming what is wrong.
  """
  @spec parse_cidr(String.t()) :: {:ok, cidr()} | {:error, String.t()}
  def parse_cidr(text) when is_binary(text) do
    case String.split(String.trim(text), "/") do
      [addr] -> with_prefix(parse(addr), nil, text)
      [addr, prefix] -> with_prefix(parse(addr), Integer.parse(prefix), text)
      _ -> {:error, "#{inspect(text)} is not an address or a CIDR"}
    end
  end

  defp with_prefix(nil, _, text), do: {:error, "#{inspect(text)} is not an address or a CIDR"}
  defp with_prefix(ip, nil, _), do: {:ok, {ip, bits(ip)}}

  defp with_prefix(ip, {prefix, ""}, text) do
    if prefix in 0..bits(ip),
      do: {:ok, {ip, prefix}},
      else: {:error, "#{inspect(text)} has a prefix outside 0..#{bits(ip)}"}
  end

  defp with_prefix(_, _, text), do: {:error, "#{inspect(text)} has a prefix that is not a number"}

  @doc "Formats an address."
  @spec to_string(ip()) :: String.t()
  def to_string(ip), do: ip |> :inet.ntoa() |> List.to_string()

  @doc "An IPv4-mapped IPv6 address as its IPv4 form; any other address unchanged."
  @spec normalize(ip()) :: ip()
  def normalize({0, 0, 0, 0, 0, 0xFFFF, hi, lo}),
    do: {hi >>> 8, hi &&& 0xFF, lo >>> 8, lo &&& 0xFF}

  def normalize(ip), do: ip

  @doc "Whether `ip` is in any of the CIDRs."
  @spec in_any?(ip(), [cidr()]) :: boolean()
  def in_any?(ip, cidrs) do
    ip = normalize(ip)
    Enum.any?(cidrs, &in_cidr?(ip, &1))
  end

  @doc "Whether `ip` is in the CIDR `{network, prefix}`. Families never match each other."
  @spec in_cidr?(ip(), cidr()) :: boolean()
  def in_cidr?(ip, {network, prefix}) when tuple_size(ip) == tuple_size(network) do
    total = bits(ip)
    mask = (1 <<< total) - (1 <<< (total - prefix))
    (to_int(ip) &&& mask) == (to_int(network) &&& mask)
  end

  def in_cidr?(_ip, _cidr), do: false

  defp bits(ip) when tuple_size(ip) == 4, do: 32
  defp bits(ip) when tuple_size(ip) == 8, do: 128

  defp to_int(ip) when tuple_size(ip) == 4,
    do: ip |> Tuple.to_list() |> Enum.reduce(0, fn part, acc -> (acc <<< 8) + part end)

  defp to_int(ip) when tuple_size(ip) == 8,
    do: ip |> Tuple.to_list() |> Enum.reduce(0, fn part, acc -> (acc <<< 16) + part end)
end
