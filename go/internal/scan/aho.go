package scan

// Автомат Aho-Corasick: все иглы ищутся за один проход по тексту.
// Раньше каждая игла (~4300) искалась отдельным strings.Index — на полном
// бэкапе (гигабайты) это триллионы сравнений и скан, упирающийся в таймаут.
// Алфавит сжат до байтов, встречающихся в иглах, — переходы хранятся
// плотной таблицей (DFA) без хешмапов.
//
// Aho-Corasick automaton: every needle is found in a single pass over the text.
// Previously each needle (~4300) ran its own strings.Index — on a full backup
// (gigabytes) that is trillions of comparisons and a scan hitting the timeout.
// The alphabet is compressed to bytes that occur in needles, so transitions
// live in a dense table (DFA) with no hash maps.

type aho struct {
	class    [256]uint8 // байт → класс (0 — байт не встречается в иглах) / byte → class (0 — not in any needle)
	nClasses int
	next     []int32 // next[state*nClasses+class]
	out      [][]int32
	dict     []int32 // ближайший суффикс-узел с выходами (-1 — нет) / nearest suffix node with outputs (-1 — none)
}

func newAho(patterns []string) *aho {
	a := &aho{}
	for _, p := range patterns {
		for i := 0; i < len(p); i++ {
			if a.class[p[i]] == 0 {
				a.nClasses++
				a.class[p[i]] = uint8(a.nClasses)
			}
		}
	}
	a.nClasses++ // + класс 0 / + class 0
	a.addState()

	for idx, p := range patterns {
		if p == "" {
			continue
		}
		s := int32(0)
		for i := 0; i < len(p); i++ {
			c := int(a.class[p[i]])
			nx := a.next[int(s)*a.nClasses+c]
			if nx == 0 {
				nx = a.addState()
				a.next[int(s)*a.nClasses+c] = nx
			}
			s = nx
		}
		a.out[s] = append(a.out[s], int32(idx))
	}

	// BFS: суффиксные ссылки и достройка переходов до полного DFA
	// BFS: failure links and completing transitions into a full DFA
	fail := make([]int32, len(a.out))
	queue := make([]int32, 0, len(a.out))
	for c := 0; c < a.nClasses; c++ {
		if nx := a.next[c]; nx != 0 {
			queue = append(queue, nx)
		}
	}
	for qi := 0; qi < len(queue); qi++ {
		s := queue[qi]
		f := fail[s]
		if len(a.out[f]) > 0 {
			a.dict[s] = f
		} else {
			a.dict[s] = a.dict[f]
		}
		for c := 0; c < a.nClasses; c++ {
			i := int(s)*a.nClasses + c
			if nx := a.next[i]; nx != 0 {
				fail[nx] = a.next[int(f)*a.nClasses+c]
				queue = append(queue, nx)
			} else {
				a.next[i] = a.next[int(f)*a.nClasses+c]
			}
		}
	}
	return a
}

func (a *aho) addState() int32 {
	a.next = append(a.next, make([]int32, a.nClasses)...)
	a.out = append(a.out, nil)
	a.dict = append(a.dict, -1)
	return int32(len(a.out) - 1)
}

// each вызывает fn(индекс иглы, позиция конца совпадения) для каждого
// вхождения в порядке текста; fn возвращает false, чтобы остановить поиск.
//
// each calls fn(needle index, match end position) for every occurrence in
// text order; fn returns false to stop the search.
func (a *aho) each(text string, fn func(idx int32, end int) bool) {
	s := int32(0)
	for i := 0; i < len(text); i++ {
		s = a.next[int(s)*a.nClasses+int(a.class[text[i]])]
		for n := s; n > 0; n = a.dict[n] {
			for _, idx := range a.out[n] {
				if !fn(idx, i+1) {
					return
				}
			}
		}
	}
}
