//
// Copyright (c) 2024 Markku Rossi
//
// All rights reserved.
//

package crypto

import (
	"testing"
)

func TestAlgorithms(t *testing.T) {
	for _, alg := range Algorithms {
		_, ok := AlgorithmsByEncType[alg.Etype]
		if !ok {
			t.Errorf("algorithm %v not found", alg.Etype)
		}
		_, ok = AlgorithmsByName[alg.Name]
		if !ok {
			t.Errorf("algorithm %s not found", alg.Name)
		}
		for _, alias := range alg.Aliases {
			_, ok = AlgorithmsByName[alias]
			if !ok {
				t.Errorf("algorithm %s (alias) not found", alias)
			}
		}
	}
}
