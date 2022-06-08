%builtins output

from starkware.cairo.common.serialize import serialize_word

func array_even_product(arr : felt*, size) -> (product):
    alloc_locals
    if size == 0:
        return (product=1)
    end

    if size == 1:
        return (product=1)
    end

    let (local product_of_rest) = array_even_product(arr=arr + 2, size=size - 2)
    return (product=[arr] * product_of_rest)
end

func main{output_ptr : felt*}():
    const ARRAY_SIZE = 6
    alloc_locals
    local array : felt* = new(1, 2, 3, 4, 5, 6)
    let (product) = array_even_product(arr=array, size=ARRAY_SIZE)

    serialize_word(product)
    
    return ()
end