%builtins range_check

from starkware.cairo.common.dict import dict_new, dict_read, dict_write, dict_squash

func main{range_check_ptr}():
    %{
        initial_dict = { 1: 2 }
    %}
    let (dict_ptr) = dict_new()
    dict_write{dict_ptr=dict_ptr}(key=1, new_value=4)
    let (res) = dict_read{dict_ptr=dict_ptr}(key=1)
    let (squashed_dict_start, squashed_dict_end) = dict_squash{
        range_check_ptr=range_check_ptr
    }(
        dict_accesses_start=dict_ptr,
        dict_accesses_end=dict_ptr
    )
    return ()
end