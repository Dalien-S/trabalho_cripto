#let template(body) = {
  set text(15pt)
  set heading(numbering: "1. ")

  // show emph: it => {
  //   set text(fill: blue)
  //   it
  // }
  //
  // show strong: it => {
  //   set text(fill: red)
  //   set strong(delta: 200)
  //   it
  // }

  set page(
    foreground: place(
      bottom + right,
      dx: -10pt,
      dy: -10pt,
      text(
        size: 7pt,
        fill: gray,
        "written in typst",
      ),
    ),
  )

  body
}

#let center_box(text) = {
  align(
    center,
    box(
      fill: luma(200),
      radius: 10pt,
      inset: 10pt,
      text,
    ),
  )
}

#let box_with_title(title, content) = {
  align(
    center,
    box(
      [
        #align(left, box(fill: blue, [#title], inset: 5pt, radius: 10pt)),
        #box(fill: red, [#content], inset: 10pt, radius: 10pt)
      ],
    ),
  )
}

