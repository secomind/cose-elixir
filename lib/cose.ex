defmodule COSE do
  @moduledoc """
  Documentation for `COSE`.
  """

  @cose_key_types %{
    okp: 1,
    symmetric: 4
  }
  def key_type(kty) when is_atom(kty), do: @cose_key_types[kty]
  def key_type(kty) when is_integer(kty), do: invert_map(@cose_key_types)[kty]

  @cose_curves %{
    x25519: 4,
    ed25519: 6
  }

  def curve(crv), do: Map.get(@cose_curves, crv, crv)

  def curve_from_id(id), do: Map.get(invert_map(@cose_curves), id, id)

  @cose_algs %{
    direct: -6,
    aes_128_gcm: 1,
    aes_192_gcm: 2,
    aes_256_gcm: 3,
    aes_ccm_16_64_128: 10,
    aes_ccm_16_64_256: 11,
    aes_ccm_64_64_128: 12,
    aes_ccm_64_64_256: 13,
    aes_ccm_16_128_128: 30,
    aes_ccm_16_128_256: 31,
    aes_ccm_64_128_128: 32,
    aes_ccm_64_128_256: 33,
    ecdh_ss_hkdf_256: -27,
    eddsa: -8,
    es256: -7,
    es384: -35,
    es512: -36,
    rs256: -257,
    rs384: -258,
    aes_128_cbc: -17760703,
    aes_128_ctr: -17760704,
    aes_256_cbc: -17760705,
    aes_256_ctr: -17760706,
    epid10: -2000810,
    epid11: -2000811
  }

  def algorithm(alg), do: Map.get(@cose_algs, alg, alg)

  def algorithm_from_id(id), do: Map.get(invert_map(@cose_algs), id, id)

  @cose_headers %{
    alg: 1,
    kid: 4,
    iv: 5,
    party_v_identity: -24
  }

  def header(hdr), do: Map.get(@cose_headers, hdr, hdr)

  def header_from_id(id), do: Map.get(invert_map(@cose_headers), id, id)

  def invert_map(a_map) do
    Enum.map(a_map, fn {key, value} -> {value, key} end) |> Enum.into(%{})
  end

  def tag_as_byte(data) when is_binary(data) do
    %CBOR.Tag{tag: :bytes, value: data}
  end

  def tag_as_byte(nil) do
    %CBOR.Tag{tag: :bytes, value: <<>>}
  end
end
