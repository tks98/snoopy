package discover

import "container/list"

// lru is a map that keeps its max most recently used entries.
type lru[K comparable, V any] struct {
	max   int
	items map[K]*list.Element
	order list.List // of lruItem, most recently used first
}

type lruItem[K comparable, V any] struct {
	key   K
	value V
}

func newLRU[K comparable, V any](max int) *lru[K, V] {
	return &lru[K, V]{max: max, items: map[K]*list.Element{}}
}

func (c *lru[K, V]) get(key K) (V, bool) {
	e, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.order.MoveToFront(e)
	return e.Value.(lruItem[K, V]).value, true
}

func (c *lru[K, V]) put(key K, value V) {
	if e, ok := c.items[key]; ok {
		e.Value = lruItem[K, V]{key, value}
		c.order.MoveToFront(e)
		return
	}
	c.items[key] = c.order.PushFront(lruItem[K, V]{key, value})
	for c.order.Len() > c.max {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.items, last.Value.(lruItem[K, V]).key)
	}
}

func (c *lru[K, V]) len() int { return c.order.Len() }
