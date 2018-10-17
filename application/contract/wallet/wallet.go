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

package wallet

import (
	"github.com/insolar/insolar/core"
	"github.com/insolar/insolar/logicrunner/goplugin/foundation"

	"github.com/insolar/insolar/application/proxy/allowance"
	"github.com/insolar/insolar/application/proxy/wallet"
)

// Wallet is a basic wallet contract
type Wallet struct {
	foundation.BaseContract
	Balance uint
}

// Allocate returns reference to a new allowance
func (w *Wallet) Allocate(amount uint, to *core.RecordRef) core.RecordRef {
	// TODO check balance is enough
	w.Balance -= amount
	ah := allowance.New(to, amount, w.GetContext().Time.Unix()+10)
	a := ah.AsChild(w.GetReference())
	return a.GetReference()
}

// Receive moves money form somebody to current wallet
func (w *Wallet) Receive(amount uint, from *core.RecordRef) {
	fromWallet := wallet.GetImplementationFrom(*from)

	v := w.GetReference()
	aRef := fromWallet.Allocate(amount, &v)
	w.Balance += allowance.GetObject(aRef).TakeAmount()
}

// Transfer moves money from current wallet to another
func (w *Wallet) Transfer(amount uint, to *core.RecordRef) {
	w.Balance -= amount

	toWallet := wallet.GetImplementationFrom(*to)
	toWalletRef := toWallet.GetReference()

	ah := allowance.New(&toWalletRef, amount, w.GetContext().Time.Unix()+10)
	a := ah.AsChild(w.GetReference())

	r := a.GetReference()
	toWallet.Accept(&r)
}

// Accept consumes allowance
func (w *Wallet) Accept(aRef *core.RecordRef) {
	w.Balance += allowance.GetObject(*aRef).TakeAmount()
}

// GetTotalBalance returns total balance including all allowances
func (w *Wallet) GetTotalBalance() uint {
	var totalAllowanced uint
	crefs, err := w.GetChildrenTyped(allowance.GetClass())
	if err != nil {
		panic(err)
	}
	for _, cref := range crefs {
		a := allowance.GetObject(cref)

		totalAllowanced += a.GetBalanceForOwner()
	}
	return w.Balance + totalAllowanced
}

// ReturnAndDeleteExpiredAllowances collects all allowances
func (w *Wallet) ReturnAndDeleteExpiredAllowances() {
	crefs, err := w.GetChildrenTyped(allowance.GetClass())
	if err != nil {
		panic(err)
	}
	for _, cref := range crefs {
		Allowance := allowance.GetObject(cref)
		w.Balance += Allowance.DeleteExpiredAllowance()
	}
}

// New creates new wallet
func New(balance uint) *Wallet {
	return &Wallet{
		Balance: balance,
	}
}
