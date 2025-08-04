import base64

import aztec_code_generator
import reportlab.graphics.widgetbase
import reportlab.lib.attrmap
import json
from io import BytesIO
from django.core.files import File
from django.core.files.storage import default_storage
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from pretix.base.pdf import Renderer as BaseRenderer
from reportlab.graphics import renderPDF
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib.colors import Color
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from pretix.plugins.ticketoutputpdf.models import TicketLayout
from pretix.plugins.ticketoutputpdf.ticketoutput import PdfTicketOutput as SuperPdfTicketOutput
from pretix.base.models import Order, OrderPosition
from . import barcode


class IsBytes(reportlab.lib.validators.Validator):
    @staticmethod
    def test(x):
        return isinstance(x, bytes)
isBytes = IsBytes()


class AztecCodeWidget(reportlab.graphics.widgetbase.Widget):
    codeName = "Aztec"
    _attrMap = reportlab.lib.attrmap.AttrMap(
        BASE = reportlab.graphics.widgetbase.Widget,
        value = reportlab.lib.attrmap.AttrMapValue(isBytes, desc='Aztec data'),
        ecLevel = reportlab.lib.attrmap.AttrMapValue(reportlab.lib.validators.isNumber, desc='Error correction percentage'),
        barFillColor = reportlab.lib.attrmap.AttrMapValue(reportlab.lib.validators.isColor, desc='bar color'),
        barWidth = reportlab.lib.attrmap.AttrMapValue(reportlab.lib.validators.isNumber, desc='Width of bars'),
        barHeight = reportlab.lib.attrmap.AttrMapValue(reportlab.lib.validators.isNumber, desc='Height of bars'),
        barBorder = reportlab.lib.attrmap.AttrMapValue(reportlab.lib.validators.isNumber, desc='Width of border'),
    )
    x = 0
    y = 0
    value = None
    ecLevel = 23
    barFillColor = reportlab.lib.colors.black
    barHeight = 32 * mm
    barWidth = 32 * mm
    barBorder = 4

    def __init__(self, value=b'Hello World', **kw):
        for k, v in kw.items():
            setattr(self, k, v)

        self.__dict__["aztec"] = aztec_code_generator.AztecCode(value, ec_percent=self.ecLevel)

    def draw(self):
        g = reportlab.graphics.shapes.Group()

        color = self.barFillColor
        border = self.barBorder
        width = self.barWidth
        height = self.barHeight
        x = self.x
        y = self.y

        g.add(reportlab.graphics.barcode.qr.SRect(x, y, width, height, fillColor=None))

        min_wh = float(min(width, height))
        box_size = min_wh / (self.aztec.size + border * 2.0)
        offset_x = x + (width - min_wh) / 2.0
        offset_y = y + (min_wh - height) / 2.0

        for y in range(self.aztec.size):
            for x in range(self.aztec.size):
                if not self.aztec.matrix[y][x]:
                    x1 = (x + border) * box_size
                    y1 = (y + border + 1) * box_size
                    s = reportlab.graphics.barcode.qr.SRect(
                        offset_x + x1, offset_y + height - y1,
                        box_size, box_size, fillColor=color
                    )
                    g.add(s)

        return g


class Renderer(BaseRenderer):
    def __init__(self, event, layout, background_file):
        super().__init__(event, layout, background_file)
        self.barcode_generator = barcode.UICBarcodeGenerator(self.event)

    def _draw_barcodearea(self, canvas: Canvas, op: OrderPosition, order: Order, o: dict):
        content = o.get('content', 'secret')

        if content == 'secret':
            content = self.barcode_generator.generate_barcode(op)
            barcode_type = "qr" if self.event.settings.uic_barcode_encoding == "b45" else "aztec"
        else:
            content = self._get_text_content(op, order, o)
            barcode_type = "qr"

        if len(content) == 0:
            return

        reqs = float(o['size']) * mm

        if barcode_type == 'qr':
            level = 'H'
            if len(content) > 32:
                level = 'M'
            if len(content) > 128:
                level = 'L'
            kwargs = {}
            if o.get('nowhitespace', False):
                kwargs['barBorder'] = 0

            if o.get('color'):
                kwargs['barFillColor'] = Color(o['color'][0] / 255, o['color'][1] / 255, o['color'][2] / 255)

            qrw = QrCodeWidget(content, barLevel=level, barHeight=reqs, barWidth=reqs, **kwargs)

        elif barcode_type == 'aztec':
            kwargs = {}
            if o.get('nowhitespace', False):
                kwargs['barBorder'] = 0

            if o.get('color'):
                kwargs['barFillColor'] = Color(o['color'][0] / 255, o['color'][1] / 255, o['color'][2] / 255)

            qrw = AztecCodeWidget(content, barHeight=reqs, barWidth=reqs, **kwargs)

        else:
            raise NotImplementedError()

        d = Drawing(reqs, reqs)
        d.add(qrw)
        qr_x = float(o['left']) * mm
        qr_y = float(o['bottom']) * mm
        renderPDF.draw(d, canvas, qr_x, qr_y)

        # Add QR content + PDF issuer as a hidden string (fully transparent & very very small)
        # This helps automated processing of the PDF file by 3rd parties, e.g. when checking tickets for resale
        data = {
            "issuer": settings.SITE_URL,
            o.get('content', 'secret'): content if isinstance(content, str) else base64.b64encode(content).decode(),
        }
        canvas.saveState()
        canvas.setFont('Open Sans', .01)
        canvas.setFillColorRGB(0, 0, 0, 0)
        canvas.drawString(0 * mm, 0 * mm, json.dumps(data, sort_keys=True))
        canvas.restoreState()


class PdfTicketOutput(SuperPdfTicketOutput):
    identifier = 'pdf-uic'
    verbose_name = _('PDF output - UIC Barcode')

    def _draw_page(self, layout: TicketLayout, op: OrderPosition, order: Order):
        buffer = BytesIO()
        objs = self.override_layout or json.loads(layout.layout) or self._legacy_layout()
        bg_file = layout.background

        if self.override_background:
            bgf = default_storage.open(self.override_background.name, "rb")
        elif isinstance(bg_file, File) and bg_file.name:
            bgf = default_storage.open(bg_file.name, "rb")
        else:
            bgf = self._get_default_background()

        p = self._create_canvas(buffer)
        renderer = Renderer(self.event, objs, bgf)
        renderer.draw_page(p, order, op)
        p.save()
        return renderer.render_background(buffer, _('Ticket'))