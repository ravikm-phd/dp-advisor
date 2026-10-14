"""Advice ordering: :before, :around, :after and call_next_advice."""

import pytest
from dp_advice import defadvice, call_next_advice, global_registry, execute_advice_chain

@pytest.fixture(autouse=True)
def clean_registry():
    global_registry.clear()

def test_lispworks_advice_execution_order():
    trace = []

    def raw_query(x: int) -> int:
        trace.append(f"target({x})")
        return x * 2

    @defadvice("test.query", name="before_check", advice_type=":before")
    def before_adv(x: int):
        trace.append("before_1")

    @defadvice("test.query", name="around_wrap", advice_type=":around")
    def around_adv(x: int):
        trace.append("around_start")
        res = call_next_advice(x + 1)
        trace.append("around_end")
        return res + 10

    @defadvice("test.query", name="after_audit", advice_type=":after")
    def after_adv(res, x: int):
        trace.append(f"after({res})")
        return res + 1

    final_val = execute_advice_chain("test.query", raw_query, 5)

    assert trace == ["around_start", "before_1", "target(6)", "after(12)", "around_end"]
    # target: 6*2 = 12, after: +1, around: +10
    assert final_val == 23

def test_multiple_around_advices():
    trace = []

    def raw_fn():
        trace.append("raw")
        return 100

    @defadvice("multi.around", name="around_outer", advice_type=":around", where=":start")
    def outer_around():
        trace.append("outer_start")
        res = call_next_advice()
        trace.append("outer_end")
        return res

    @defadvice("multi.around", name="around_inner", advice_type=":around", where=":end")
    def inner_around():
        trace.append("inner_start")
        res = call_next_advice()
        trace.append("inner_end")
        return res

    res = execute_advice_chain("multi.around", raw_fn)
    assert trace == ["outer_start", "inner_start", "raw", "inner_end", "outer_end"]
    assert res == 100
