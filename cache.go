package main

import (
	"sync"
	"time"
)

type Element struct {
	Value            *Answer
	TimeAdded        int64
	IsWildcardDomain bool
}

type Cache struct {
	elements     map[string]Element
	egressPolicy string
	mutex        sync.RWMutex
}

func InitCache(egressPolicy string) Cache {
	return Cache{
		elements:     make(map[string]Element),
		egressPolicy: egressPolicy,
	}
}

func (cache *Cache) Get(k string) (*Element, bool) {
	cache.mutex.RLock()

	element, found := cache.elements[k]
	if !found {
		cache.mutex.RUnlock()
		return nil, false
	}

	if cache.egressPolicy == EgressPolicyAudit || element.IsWildcardDomain {
		// TTL is in seconds
		// if now minus time added is greater than TTL, return nil, so new DNS request is made
		if time.Now().Unix()-element.TimeAdded > int64(element.Value.TTL) {
			cache.mutex.RUnlock()
			return nil, false
		} else {
			cache.mutex.RUnlock()
			return &element, true
		}
	} else {
		// for block scenario
		// return the found value
		// a separate thread updates the cache before TTL expires
		cache.mutex.RUnlock()
		return &element, true
	}
}

func (cache *Cache) Set(k string, v *Answer, isWildcardDomain bool) {
	cache.mutex.Lock()

	cache.elements[k] = Element{
		Value:            v,
		TimeAdded:        time.Now().Unix(),
		IsWildcardDomain: isWildcardDomain,
	}

	cache.mutex.Unlock()
}
