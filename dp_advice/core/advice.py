"""A small Python version of the LispWorks advice facility (defadvice).

Supports :before, :around and :after advice, placed at :start or :end of their chain.
"""

import threading
from typing import Callable, List, Dict, Any, Optional

# per-thread, so nested and concurrent calls don't trip over each other
_advice_context = threading.local()

class AdviceContext:
    def __init__(self, target_fn: Callable, around_chain: List[Callable],
                 before_chain: List[Callable], after_chain: List[Callable]):
        self.target_fn = target_fn
        self.around_chain = around_chain
        self.before_chain = before_chain
        self.after_chain = after_chain
        self.around_index = 0

def call_next_advice(*args, **kwargs) -> Any:
    """Continue from inside :around advice.

    Runs the next :around advice if there is one, otherwise the :before advice,
    the target and the :after advice. An :after advice that returns something
    other than None replaces the result.
    """
    ctx: Optional[AdviceContext] = getattr(_advice_context, 'current', None)
    if ctx is None:
        raise RuntimeError("call_next_advice() can only be called from within an :around advice execution context.")

    if ctx.around_index < len(ctx.around_chain):
        next_around = ctx.around_chain[ctx.around_index]
        ctx.around_index += 1
        try:
            return next_around(*args, **kwargs)
        finally:
            ctx.around_index -= 1
    else:
        for before_fn in ctx.before_chain:
            before_fn(*args, **kwargs)

        res = ctx.target_fn(*args, **kwargs)

        final_res = res
        for after_fn in ctx.after_chain:
            out = after_fn(final_res, *args, **kwargs)
            if out is not None:
                final_res = out

        return final_res


class AdviceRegistry:
    def __init__(self):
        self._registry: Dict[str, Dict[str, List[Callable]]] = {}
        self._lock = threading.Lock()

    def register_advice(self, target_key: str, name: str, advice_type: str,
                        advice_fn: Callable, where: str = ":start") -> None:
        advice_type = advice_type.lower()
        if advice_type not in (":before", "before", ":around", "around", ":after", "after"):
            raise ValueError(f"Invalid advice_type '{advice_type}'. Must be :before, :around, or :after.")

        norm_type = advice_type.lstrip(":")

        with self._lock:
            if target_key not in self._registry:
                self._registry[target_key] = {"around": [], "before": [], "after": []}

            chain = self._registry[target_key][norm_type]
            # re-registering a name replaces the old advice
            chain[:] = [fn for fn in chain if getattr(fn, '__advice_name__', None) != name]
            advice_fn.__advice_name__ = name

            if where == ":end":
                chain.append(advice_fn)
            else:
                chain.insert(0, advice_fn)

    def get_chains(self, target_key: str) -> Dict[str, List[Callable]]:
        with self._lock:
            chains = self._registry.get(target_key, {"around": [], "before": [], "after": []})
            return {
                "around": list(chains["around"]),
                "before": list(chains["before"]),
                "after": list(chains["after"])
            }

    def clear(self) -> None:
        with self._lock:
            self._registry.clear()


global_registry = AdviceRegistry()


def defadvice(target_key: str, name: str, advice_type: str, where: str = ":start"):
    """Decorator form of register_advice.

        @defadvice("diffprivlib.Laplace", name="verify_params", advice_type=":before")
        def check_params(*args, **kwargs):
            ...
    """
    def decorator(fn: Callable):
        global_registry.register_advice(target_key, name, advice_type, fn, where)
        return fn
    return decorator


def execute_advice_chain(target_key: str, original_fn: Callable, *args, **kwargs) -> Any:
    """Run original_fn through whatever advice is registered for target_key."""
    chains = global_registry.get_chains(target_key)
    ctx = AdviceContext(
        target_fn=original_fn,
        around_chain=chains["around"],
        before_chain=chains["before"],
        after_chain=chains["after"]
    )

    prev_ctx = getattr(_advice_context, 'current', None)
    _advice_context.current = ctx
    try:
        return call_next_advice(*args, **kwargs)
    finally:
        _advice_context.current = prev_ctx
