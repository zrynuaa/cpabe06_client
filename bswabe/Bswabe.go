package bswabe

import (
	"github.com/Nik-U/pbc"
	"fmt"
	"strings"
	"strconv"
	"crypto/sha1"
)

//Delegate a subset of attribute of an existing private key.

func Delegate(pub *BswabePub, prv_src *BswabePrv, attrs_subset []string) *BswabePrv {

	prv := new(BswabePrv)
	var g_rt, rt, f_at_rt *pbc.Element
	var pairing *pbc.Pairing

	/* initialize */
	pairing = pub.p
	prv.d = pairing.NewG2()

	g_rt = pairing.NewG2()
	rt = pairing.NewZr()
	f_at_rt = pairing.NewZr()

	/* compute */
	rt.Rand()
	f_at_rt = pub.f.NewFieldElement().Set(pub.f)
	f_at_rt.PowZn(f_at_rt, rt)
	prv.d = prv_src.d.NewFieldElement().Set(prv_src.d)
	prv.d.Mul(prv.d, f_at_rt)

	g_rt = pub.g.NewFieldElement().Set(pub.g)
	g_rt.PowZn(g_rt, rt)

	//len = attrs_subset.length
	//prv.comps = new ArrayList<BswabePrvComp>();

	for i := 0; i < len(attrs_subset); i++ {
		comp := new(BswabePrvComp)
		var h_rtp *pbc.Element
		var rtp *pbc.Element

		comp.attr = attrs_subset[i]

		comp_src := new(BswabePrvComp)
		comp_src_init := false

		for j := 0; j < len(prv_src.comps); j++ {
			if strings.Compare(prv_src.comps[j].attr, comp.attr) == 0 {
				comp_src = prv_src.comps[j]
				comp_src_init = true
				break
			}
		}

		if comp_src_init == false {
			panic("comp_src_init == false")
		}

		comp.d = pairing.NewG2()
		comp.dp = pairing.NewG1()
		h_rtp = pairing.NewG2()
		rtp = pairing.NewZr()

		elementFromString(h_rtp, comp.attr);
		rtp.Rand()

		h_rtp.PowZn(h_rtp, rtp)

		comp.d = g_rt.NewFieldElement().Set(g_rt)
		comp.d.Mul(comp.d, h_rtp)
		comp.d.Mul(comp.d, comp_src.d)

		comp.dp = pub.g.NewFieldElement().Set(pub.g)
		comp.dp.PowZn(comp.dp, rtp)
		comp.dp.Mul(comp.dp, comp_src.dp)

		prv.comps = append(prv.comps,comp)
		//prv.comps.add(comp);
	}

	return prv
}

func Enc(pub *BswabePub, policy string) (*BswabeCphKey, *pbc.Element) {
	keyCph := new(BswabeCphKey)
	cph := new(BswabeCph)
	var s, m *pbc.Element

	/* initialize */
	pairing := pub.p;
	s = pairing.NewZr()
	m = pairing.NewGT()
	cph.cs = pairing.NewGT()
	cph.c = pairing.NewG1()
	cph.p = parsePolicyPostfix(policy)

	/* compute */
	m.Rand()
	s.Rand()
	cph.s = s.NewFieldElement().Set(s)
	cph.cs = pub.g_hat_alpha.NewFieldElement().Set(pub.g_hat_alpha)
	cph.cs.PowZn(cph.cs, s) 	/* num_exps++; */
	cph.cs.Mul(cph.cs, m) 		/* num_muls++; */

	cph.c = pub.h.NewFieldElement().Set(pub.h)
	cph.c.PowZn(cph.c, s) 		/* num_exps++; */

	fillPolicy(cph.p, pub, s)

	keyCph.Cph = cph
	//keyCph.Key = m //TODO

	return keyCph, m
}

func Dec(pub *BswabePub, prv *BswabePrv, cph *BswabeCph) *BswabeElementBoolean {
	var t, m *pbc.Element
	beb := new(BswabeElementBoolean)

	m = pub.p.NewGT()
	t = pub.p.NewGT()

	checkSatisfy(cph.p, prv)
	if (!cph.p.satisfiable) {
		fmt.Println("cannot decrypt, attributes in key do not satisfy policy")
		beb.E = nil
		beb.B = false
		return beb
	}

	pickSatisfyMinLeaves(cph.p, prv)
	decFlatten(t, cph.p, prv, pub)

	m = cph.cs.NewFieldElement().Set(cph.cs)
	m.Mul(m, t) 		/* num_muls++; */

	t.Pair(cph.c, prv.d)
	t.Invert(t)
	m.Mul(m, t) 		/* num_muls++; */

	beb.E = m
	beb.B = true
	return beb
}

func decFlatten(r *pbc.Element, p *BswabePolicy, prv *BswabePrv, pub *BswabePub) {
	var one *pbc.Element
	one = pub.p.NewZr()
	one.Set1()
	r.Set1()

	decNodeFlatten(r, one, p, prv, pub)
}

func decNodeFlatten(r *pbc.Element, exp *pbc.Element, p *BswabePolicy, prv *BswabePrv, pub *BswabePub) {
	if p.children == nil || len(p.children) == 0 {
		decLeafFlatten(r, exp, p, prv, pub)
	} else {
		decInternalFlatten(r, exp, p, prv, pub)
	}
}

func decLeafFlatten(r *pbc.Element, exp *pbc.Element, p *BswabePolicy, prv *BswabePrv, pub *BswabePub) {
	c := new(BswabePrvComp)
	var s, t *pbc.Element

	c = prv.comps[p.attri]

	s = pub.p.NewGT()
	t = pub.p.NewGT()

	s.Pair(p.c, c.d) 	/* num_pairings++; */
	t.Pair(p.cp, c.dp) 	/* num_pairings++; */
	t.Invert(t)
	s.Mul(s, t) 		/* num_muls++; */
	s.PowZn(s, exp) 	/* num_exps++; */

	r.Mul(r, s) 		/* num_muls++; */
}

func decInternalFlatten(r *pbc.Element, exp *pbc.Element, p *BswabePolicy, prv *BswabePrv, pub *BswabePub) {
	var i int
	var t, expnew *pbc.Element

	t = pub.p.NewZr()
	expnew = pub.p.NewZr()

	for i = 0; i < len(p.satl); i++ {
		lagrangeCoef(t, p.satl, p.satl[i])
		expnew = exp.NewFieldElement().Set(exp)
		expnew.Mul(expnew, t)
		decNodeFlatten(r, expnew, p.children[p.satl[i] - 1], prv, pub)
	}
}

func lagrangeCoef(r *pbc.Element, s []int, i int) {
	var j, k int
	var t *pbc.Element

	t = r.NewFieldElement().Set(r)

	r.Set1()
	for k = 0; k < len(s); k++ {
		j = s[k]
		if j == i {
			continue
		}
		t.SetInt32(int32(-j))
		r.Mul(r, t) 	/* num_muls++; */
		t.SetInt32(int32(i - j))
		t.Invert(t)
		r.Mul(r, t) 	/* num_muls++; */
	}
}

func pickSatisfyMinLeaves(p *BswabePolicy, prv *BswabePrv) {
	var i, k, l, c_i int
	var c []int

	if p.children == nil || len(p.children) == 0 {
		p.min_leaves = 1
	} else {
		len := len(p.children)
		for i = 0; i < len; i++ {
			if (p.children[i].satisfiable) {
				pickSatisfyMinLeaves(p.children[i], prv)
			}
		}

		for i = 0; i < len; i++ {
			c = append(c, i)
		}

		//TODO 这里的排序需要进一步改写,min_leaves是从小到大排序的，用了很low的冒泡排序。。。
		for i := 0; i < len; i++ {
			for j := 0; j < len-i-1; j++ {
				if p.children[c[j]].min_leaves > p.children[c[j+1]].min_leaves {
					c[j], c[j+1] = c[j+1], c[j]
				}
			}
		}

		p.min_leaves = 0
		l = 0

		for i = 0; i < len && l < p.k; i++ {
			c_i = c[i] /* c[i] */
			if p.children[c_i].satisfiable {
				l++
				p.min_leaves += p.children[c_i].min_leaves
				k = c_i + 1
				p.satl = append(p.satl, k)
			}
		}
	}
}

func checkSatisfy(p *BswabePolicy, prv *BswabePrv) {
	var i, l int
	var prvAttr string

	p.satisfiable = false
	if p.children == nil || len(p.children) == 0 {
	for i = 0; i < len(prv.comps); i++ {
		prvAttr = prv.comps[i].attr
		if strings.Compare(prvAttr,p.attr) == 0 {
			p.satisfiable = true
			p.attri = i
			break
		}
	}
	} else {
		for i = 0; i < len(p.children); i++ {
			checkSatisfy(p.children[i], prv)
		}

		l = 0;
		for i = 0; i < len(p.children); i++ {
			if (p.children[i].satisfiable) {
				l++;
			}
		}

		if (l >= p.k) {
			p.satisfiable = true
		}
	}
}

func fillPolicy(p *BswabePolicy, pub *BswabePub, e *pbc.Element) {
	var i int
	var r, t, h *pbc.Element
	pairing := pub.p
	r = pairing.NewZr()
	t = pairing.NewZr()
	h = pairing.NewG2()

	p.q = randPoly(p.k - 1, e)

	if p.children == nil || len(p.children) == 0 {
		p.c = pairing.NewG1()
		p.cp = pairing.NewG2()

		elementFromString(h, p.attr)
		p.c = pub.g.NewFieldElement().Set(pub.g)
		p.c.PowZn(p.c, p.q.coef[0])
		p.cp = h.NewFieldElement().Set(h)
		p.cp.PowZn(p.cp, p.q.coef[0])
	} else {
		for i = 0; i < len(p.children); i++ {
			r.SetInt32(int32(i + 1))
			evalPoly(t, p.q, r)
			fillPolicy(p.children[i], pub, t)
		}
	}

}

func evalPoly(r *pbc.Element, q *BswabePolynomial, x *pbc.Element) {
	var i int
	var s, t *pbc.Element

	s = r.NewFieldElement().Set(r)
	t = r.NewFieldElement().Set(r)

	r.Set0()
	t.Set1()

	for i = 0; i < q.deg + 1; i++ {
		/* r += q->coef[i] * t */
		s = q.coef[i].NewFieldElement().Set(q.coef[i])
		s.Mul(s, t)
		r.Add(r, s)

		/* t *= x */
		t.Mul(t, x)
	}

}

func randPoly(deg int, zeroVal *pbc.Element) *BswabePolynomial {
	var i int
	q := new(BswabePolynomial)
	q.deg = deg
	q.coef = make([]*pbc.Element, deg+1)

	for i = 0; i < deg+1; i++ {
		q.coef[i] = zeroVal.NewFieldElement().Set(zeroVal)
	}

	q.coef[0].Set(zeroVal)

	for i = 1; i < deg+1; i++ {
		q.coef[i].Rand()
	}

	return q;
}

func parsePolicyPostfix(s string) *BswabePolicy {
	var toks []string
	var tok string
	var stack []*BswabePolicy
	var root *BswabePolicy

	toks = strings.Split(s, " ")

	toks_cnt := len(toks)
	for index := 0; index < toks_cnt; index++ {
		var i, k, n int

		tok = toks[index]
		if !strings.Contains(tok, "of") {
			stack = append(stack, baseNode(1, tok))
		} else {
			var node *BswabePolicy

			/* parse k of n node */
			k_n := strings.Split(tok, "of")
			k,_ = strconv.Atoi(k_n[0])
			n,_ = strconv.Atoi(k_n[1])

			if k < 1 {
				fmt.Println("error parsing " + s + ": trivially satisfied operator " + tok)
				return nil
			} else if k > n {
				fmt.Println("error parsing " + s + ": unsatisfiable operator " + tok)
				return nil
			} else if n == 1 {
				fmt.Println("error parsing " + s+ ": indentity operator " + tok)
				return nil
			} else if n > len(stack) {
				fmt.Println("error parsing " + s + ": stack underflow at " + tok)
				return nil
			}

			/* pop n things and fill in children */
			node = baseNode(k, "")
			node.children = make([]*BswabePolicy,n)

			for i = n - 1; i >= 0; i-- {
				node.children[i] = stack[len(stack) - 1]
				stack = stack[:len(stack)-1]
			}

			/* push result */
			stack = append(stack, node)
		}
	}

	if len(stack) > 1 {
		fmt.Println("error parsing " + s + ": extra node left on the stack")
		return nil
	} else if len(stack) < 1 {
		fmt.Println("error parsing " + s + ": empty policy")
		return nil
	}

	root = stack[0]
	return root
}

func baseNode(k int, s string) *BswabePolicy {
	p := new(BswabePolicy)

	p.k = k
	if !(s == "") {
		p.attr = s
	} else {
		p.attr = ""
	}
	p.q = nil

	return p
}

func elementFromString(h *pbc.Element, s string) {
	sha := sha1.Sum([]byte(s))
	digest := sha[:]
	h.SetFromHash(digest)
}
