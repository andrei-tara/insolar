/*
 *    Copyright 2018 Insolar
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package main

import (
	"fmt"
	"io"
	"sync"
)

type scenario interface {
	canBeStarted() error
	start()
	getOperationsNumber() int
	getName() string
	getOut() io.Writer
}

type transferDifferentMembersScenario struct {
	name        string
	concurrent  int
	repetitions int
	members     []string
	out         io.Writer
}

func (s *transferDifferentMembersScenario) getOperationsNumber() int {
	return s.concurrent * s.repetitions
}

func (s *transferDifferentMembersScenario) getName() string {
	return s.name
}

func (s *transferDifferentMembersScenario) getOut() io.Writer {
	return s.out
}

func (s *transferDifferentMembersScenario) canBeStarted() error {
	if len(s.members) < s.concurrent*s.repetitions*2 {
		return fmt.Errorf("not enough members for scenario %s", s.getName())
	}
	return nil
}

func (s *transferDifferentMembersScenario) start() {
	var wg sync.WaitGroup
	for i := 0; i < s.concurrent*s.repetitions*2; i = i + s.repetitions*2 {
		wg.Add(1)
		go s.startMember(i, &wg)
	}
	wg.Wait()
}

func (s *transferDifferentMembersScenario) startMember(index int, wg *sync.WaitGroup) {
	defer wg.Done()
	for j := 0; j < s.repetitions*2; j = j + 2 {
		from := s.members[index+j]
		to := s.members[index+j+1]
		response := transfer(1, from, to)
		writeToOutput(s.out, fmt.Sprintf("[Member №%d] Transfer from %s to %s. Response: %s.\n", index, from, to, response))
	}
}
