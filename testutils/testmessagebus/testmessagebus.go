/*
 *
 *  *    Copyright 2018 Insolar
 *  *
 *  *    Licensed under the Apache License, Version 2.0 (the "License");
 *  *    you may not use this file except in compliance with the License.
 *  *    You may obtain a copy of the License at
 *  *
 *  *        http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  *    Unless required by applicable law or agreed to in writing, software
 *  *    distributed under the License is distributed on an "AS IS" BASIS,
 *  *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  *    See the License for the specific language governing permissions and
 *  *    limitations under the License.
 *
 */

package testmessagebus

import (
	"errors"
	"fmt"

	"github.com/insolar/insolar/core"
)

type TestMessageBus struct {
	handlers map[core.MessageType]core.MessageHandler
}

func NewTestMessageBus() *TestMessageBus {
	return &TestMessageBus{handlers: map[core.MessageType]core.MessageHandler{}}
}

func (mb *TestMessageBus) Register(p core.MessageType, handler core.MessageHandler) error {
	_, ok := mb.handlers[p]
	if ok {
		return errors.New("handler for this type already exists")
	}

	mb.handlers[p] = handler
	return nil
}

func (mb *TestMessageBus) ReRegister(p core.MessageType, handler core.MessageHandler) {
	mb.handlers[p] = handler
}

func (mb *TestMessageBus) MustRegister(p core.MessageType, handler core.MessageHandler) {
	err := mb.Register(p, handler)
	if err != nil {
		panic(err)
	}
}

func (mb *TestMessageBus) Start(components core.Components) error {
	panic("implement me")
}

func (mb *TestMessageBus) Stop() error {
	panic("implement me")
}

func (mb *TestMessageBus) Send(m core.Message) (core.Reply, error) {
	t := m.Type()
	handler, ok := mb.handlers[t]
	if !ok {
		return nil, errors.New(fmt.Sprint("no handler for message type:", t.String()))
	}

	return handler(m)
}

func (mb *TestMessageBus) SendAsync(m core.Message) {
	panic("implement me")
}
