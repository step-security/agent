package main

import (
	"sync"
	"time"
)

type Element struct {
	Value     interface{}
	TimeAdded int64
}

type Cache struct {
	elements       map[string]Element
	mutex          sync.RWMutex
	expirationTime int64
}

func InitCache(expirationTime int64) Cache {
	return Cache{
		elements:       make(map[string]Element),
		expirationTime: expirationTime,
	}
}

func (cache *Cache) Get(k string) (interface{}, bool) {
	cache.mutex.RLock()

	element, found := cache.elements[k]
	if !found {
		cache.mutex.RUnlock()
		return "", false
	}
	if cache.expirationTime > 0 {
		if time.Now().UnixNano()-cache.expirationTime > element.TimeAdded {
			cache.mutex.RUnlock()
			return "", false
		}
	}

	cache.mutex.RUnlock()
	return element.Value, true
}

func (cache *Cache) Set(k string, v interface{}) {
	cache.mutex.Lock()

	cache.elements[k] = Element{
		Value:     v,
		TimeAdded: time.Now().UnixNano(),
	}

	cache.mutex.Unlock()
}
