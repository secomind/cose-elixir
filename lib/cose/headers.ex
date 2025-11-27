defmodule COSE.Headers do
  def translate(phdr) do
    phdr
    |> Enum.map(fn {k, v} ->
      cond do
        k == :alg || k == 1 ->
          {COSE.header(k), COSE.algorithm(v)}

        true ->
          {COSE.header(k), v}
      end
    end)
    # FIXME: this may alter the order of the elements. TO-DO: think of a way to solve it.
    |> Enum.into(%{})
  end

  def translate_back(phdr) do
    phdr
    |> Enum.map(fn {k, v} ->
      cond do
        k == :alg || k == 1 ->
          {COSE.header_from_id(k), COSE.algorithm_from_id(v)}

        true ->
          {COSE.header_from_id(k), v}
      end
    end)
    # FIXME: this may alter the order of the elements. TO-DO: think of a way to solve it.
    |> Enum.into(%{})
  end

  def tag_phdr(phdr_map) do
    COSE.tag_as_byte(CBOR.encode(translate(phdr_map)))
  end

  def decode_phdr(phdr_bytes) do
    {:ok, phdr_map, ""} = CBOR.decode(phdr_bytes.value)
    translate_back(phdr_map)
  end
end
