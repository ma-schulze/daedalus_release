from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params

def sym_input_0811_a(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


def sym_input_1449(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


def sym_input_d78d(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

def sym_input_df1ed(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


def sym_input_0811_a_vuln(state):
    p3 = init_params(state)

    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


def sym_input_df1ed_vuln(state):
    p3 = init_params(state)

    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state