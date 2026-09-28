package api

import (
	"sync"
	"testing"
	"time"
)

func TestChangesNotifyWakesEveryWaiter(t *testing.T) {
	c := NewChanges()
	const waiters = 3
	var waiting sync.WaitGroup
	woken := make(chan struct{}, waiters)
	for range waiters {
		waiting.Add(1)
		go func() {
			ch := c.wait()
			waiting.Done()
			<-ch
			woken <- struct{}{}
		}()
	}
	waiting.Wait()

	c.Notify()
	for i := range waiters {
		select {
		case <-woken:
		case <-time.After(5 * time.Second):
			t.Fatalf("one Notify woke %d of %d waiters", i, waiters)
		}
	}
}

func TestChangesNotifyWithoutWaitersDoesNotBlock(t *testing.T) {
	c := NewChanges()
	var notifiers sync.WaitGroup
	for range 8 {
		notifiers.Go(func() {
			for range 100 {
				c.Notify()
			}
		})
	}
	done := make(chan struct{})
	go func() {
		notifiers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Notify blocked without waiters")
	}
}

// A handler takes the channel before it reads the store, so a Notify that
// comes after that read must close the channel it holds.
func TestChangesWaitObservesLaterNotify(t *testing.T) {
	c := NewChanges()
	before := c.wait()
	select {
	case <-before:
		t.Fatal("channel closed before any Notify")
	default:
	}

	c.Notify()
	select {
	case <-before:
	default:
		t.Fatal("Notify did not close the channel taken before it")
	}
	select {
	case <-c.wait():
		t.Fatal("a channel taken after Notify is already closed")
	default:
	}
}
